/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"net"
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"github.com/NOXCIS/wiregate-windows-client/l18n"
	"github.com/NOXCIS/wiregate-windows-client/manager"
	"github.com/NOXCIS/wiregate-windows-client/ui/syntax"
	"github.com/NOXCIS/wiregate-windows/conf"
)

type EditDialog struct {
	*walk.Dialog
	nameEdit                        *walk.LineEdit
	pubkeyEdit                      *walk.LineEdit
	syntaxEdit                      *syntax.SyntaxEdit
	blockUntunneledTrafficCB        *walk.CheckBox
	saveButton                      *walk.PushButton
	config                          conf.Config
	lastPrivateKey                  string
	blockUntunneledTraficCheckGuard bool
	
	// TLS Pipe controls (for first peer)
	tlsPipeGroup                    *walk.GroupBox
	tlsPipeEnabledCB               *walk.CheckBox
	tlsPipePasswordEdit            *walk.LineEdit
	tlsPipeServerNameEdit          *walk.LineEdit
	tlsPipeSecureCB                *walk.CheckBox
	tlsPipeProxyEdit               *walk.LineEdit
	tlsPipeFingerprintCombo         *walk.ComboBox
	
	// Split Tunneling controls (for interface)
	splitTunnelingGroup            *walk.GroupBox
	splitTunnelingModeCombo         *walk.ComboBox
	splitTunnelingSitesEdit        *walk.LineEdit
	
	updatingFromText               bool
}

func runEditDialog(owner walk.Form, tunnel *manager.Tunnel) *conf.Config {
	dlg, err := newEditDialog(owner, tunnel)
	if showError(err, owner) {
		return nil
	}

	if dlg.Run() == walk.DlgCmdOK {
		return &dlg.config
	}

	return nil
}

func newEditDialog(owner walk.Form, tunnel *manager.Tunnel) (*EditDialog, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg := new(EditDialog)

	var title string
	if tunnel == nil {
		title = l18n.Sprintf("Create new tunnel")
	} else {
		title = l18n.Sprintf("Edit tunnel")
	}

	if tunnel == nil {
		// Creating a new tunnel, create a new private key and use the default template
		pk, _ := conf.NewPrivateKey()
		dlg.config = conf.Config{Interface: conf.Interface{PrivateKey: *pk}}
	} else {
		dlg.config, _ = tunnel.StoredConfig()
	}

	layout := walk.NewGridLayout()
	layout.SetSpacing(6)
	layout.SetMargins(walk.Margins{10, 10, 10, 10})
	layout.SetColumnStretchFactor(1, 3)

	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		return nil, err
	}
	disposables.Add(dlg)
	dlg.SetIcon(owner.Icon())
	dlg.SetTitle(title)
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{500, 500}, walk.Size{0, 0})
	if icon, err := loadSystemIcon("imageres", -114, 32); err == nil {
		dlg.SetIcon(icon)
	}

	nameLabel, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(nameLabel, walk.Rectangle{0, 0, 1, 1})
	nameLabel.SetTextAlignment(walk.AlignHFarVCenter)
	nameLabel.SetText(l18n.Sprintf("&Name:"))

	if dlg.nameEdit, err = walk.NewLineEdit(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.nameEdit, walk.Rectangle{1, 0, 1, 1})
	dlg.nameEdit.SetText(dlg.config.Name)

	pubkeyLabel, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pubkeyLabel, walk.Rectangle{0, 1, 1, 1})
	pubkeyLabel.SetTextAlignment(walk.AlignHFarVCenter)
	pubkeyLabel.SetText(l18n.Sprintf("&Public key:"))

	if dlg.pubkeyEdit, err = walk.NewLineEdit(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.pubkeyEdit, walk.Rectangle{1, 1, 1, 1})
	dlg.pubkeyEdit.SetReadOnly(true)
	dlg.pubkeyEdit.SetText(l18n.Sprintf("(unknown)"))
	dlg.pubkeyEdit.Accessibility().SetRole(walk.AccRoleStatictext)

	// Create TLS Pipe controls group
	if dlg.tlsPipeGroup, err = walk.NewGroupBox(dlg); err != nil {
		return nil, err
	}
	dlg.tlsPipeGroup.SetTitle(l18n.Sprintf("TLS Pipe (UdpTlsPipe)"))
	tlsPipeLayout := walk.NewGridLayout()
	tlsPipeLayout.SetSpacing(6)
	tlsPipeLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	dlg.tlsPipeGroup.SetLayout(tlsPipeLayout)
	layout.SetRange(dlg.tlsPipeGroup, walk.Rectangle{0, 2, 2, 1})
	
	row := 0
	tlsEnabledLabel, _ := walk.NewTextLabel(dlg.tlsPipeGroup)
	tlsEnabledLabel.SetText(l18n.Sprintf("&Enabled:"))
	tlsPipeLayout.SetRange(tlsEnabledLabel, walk.Rectangle{0, row, 1, 1})
	if dlg.tlsPipeEnabledCB, err = walk.NewCheckBox(dlg.tlsPipeGroup); err != nil {
		return nil, err
	}
	tlsPipeLayout.SetRange(dlg.tlsPipeEnabledCB, walk.Rectangle{1, row, 1, 1})
	dlg.tlsPipeEnabledCB.CheckedChanged().Attach(dlg.onTlsPipeEnabledChanged)
	row++
	
	tlsPasswordLabel, _ := walk.NewTextLabel(dlg.tlsPipeGroup)
	tlsPasswordLabel.SetText(l18n.Sprintf("&Password:"))
	tlsPipeLayout.SetRange(tlsPasswordLabel, walk.Rectangle{0, row, 1, 1})
	if dlg.tlsPipePasswordEdit, err = walk.NewLineEdit(dlg.tlsPipeGroup); err != nil {
		return nil, err
	}
	tlsPipeLayout.SetRange(dlg.tlsPipePasswordEdit, walk.Rectangle{1, row, 1, 1})
	dlg.tlsPipePasswordEdit.SetPasswordMode(true)
	dlg.tlsPipePasswordEdit.TextChanged().Attach(dlg.onTlsPipeFieldChanged)
	row++
	
	tlsServerNameLabel, _ := walk.NewTextLabel(dlg.tlsPipeGroup)
	tlsServerNameLabel.SetText(l18n.Sprintf("TLS &Server Name:"))
	tlsPipeLayout.SetRange(tlsServerNameLabel, walk.Rectangle{0, row, 1, 1})
	if dlg.tlsPipeServerNameEdit, err = walk.NewLineEdit(dlg.tlsPipeGroup); err != nil {
		return nil, err
	}
	tlsPipeLayout.SetRange(dlg.tlsPipeServerNameEdit, walk.Rectangle{1, row, 1, 1})
	dlg.tlsPipeServerNameEdit.TextChanged().Attach(dlg.onTlsPipeFieldChanged)
	row++
	
	tlsSecureLabel, _ := walk.NewTextLabel(dlg.tlsPipeGroup)
	tlsSecureLabel.SetText(l18n.Sprintf("&Secure (verify certificate):"))
	tlsPipeLayout.SetRange(tlsSecureLabel, walk.Rectangle{0, row, 1, 1})
	if dlg.tlsPipeSecureCB, err = walk.NewCheckBox(dlg.tlsPipeGroup); err != nil {
		return nil, err
	}
	tlsPipeLayout.SetRange(dlg.tlsPipeSecureCB, walk.Rectangle{1, row, 1, 1})
	dlg.tlsPipeSecureCB.CheckedChanged().Attach(dlg.onTlsPipeFieldChanged)
	row++
	
	tlsProxyLabel, _ := walk.NewTextLabel(dlg.tlsPipeGroup)
	tlsProxyLabel.SetText(l18n.Sprintf("&Proxy URL:"))
	tlsPipeLayout.SetRange(tlsProxyLabel, walk.Rectangle{0, row, 1, 1})
	if dlg.tlsPipeProxyEdit, err = walk.NewLineEdit(dlg.tlsPipeGroup); err != nil {
		return nil, err
	}
	tlsPipeLayout.SetRange(dlg.tlsPipeProxyEdit, walk.Rectangle{1, row, 1, 1})
	dlg.tlsPipeProxyEdit.SetToolTipText(l18n.Sprintf("e.g., socks5://user:pass@host:port"))
	dlg.tlsPipeProxyEdit.TextChanged().Attach(dlg.onTlsPipeFieldChanged)
	row++
	
	tlsFingerprintLabel, _ := walk.NewTextLabel(dlg.tlsPipeGroup)
	tlsFingerprintLabel.SetText(l18n.Sprintf("Fingerprint &Profile:"))
	tlsPipeLayout.SetRange(tlsFingerprintLabel, walk.Rectangle{0, row, 1, 1})
	if dlg.tlsPipeFingerprintCombo, err = walk.NewComboBox(dlg.tlsPipeGroup); err != nil {
		return nil, err
	}
	tlsPipeLayout.SetRange(dlg.tlsPipeFingerprintCombo, walk.Rectangle{1, row, 1, 1})
	dlg.tlsPipeFingerprintCombo.SetModel([]string{"", "chrome", "firefox", "safari", "edge", "okhttp", "ios", "randomized"})
	dlg.tlsPipeFingerprintCombo.TextChanged().Attach(dlg.onTlsPipeFieldChanged)
	
	// Create Split Tunneling controls group
	if dlg.splitTunnelingGroup, err = walk.NewGroupBox(dlg); err != nil {
		return nil, err
	}
	dlg.splitTunnelingGroup.SetTitle(l18n.Sprintf("Split Tunneling"))
	splitLayout := walk.NewGridLayout()
	splitLayout.SetSpacing(6)
	splitLayout.SetMargins(walk.Margins{10, 10, 10, 10})
	dlg.splitTunnelingGroup.SetLayout(splitLayout)
	layout.SetRange(dlg.splitTunnelingGroup, walk.Rectangle{0, 3, 2, 1})
	
	splitModeLabel, _ := walk.NewTextLabel(dlg.splitTunnelingGroup)
	splitModeLabel.SetText(l18n.Sprintf("&Mode:"))
	splitLayout.SetRange(splitModeLabel, walk.Rectangle{0, 0, 1, 1})
	if dlg.splitTunnelingModeCombo, err = walk.NewComboBox(dlg.splitTunnelingGroup); err != nil {
		return nil, err
	}
	splitLayout.SetRange(dlg.splitTunnelingModeCombo, walk.Rectangle{1, 0, 1, 1})
	dlg.splitTunnelingModeCombo.SetModel([]string{
		l18n.Sprintf("All sites (default)"),
		l18n.Sprintf("Only forward specified sites"),
		l18n.Sprintf("All except specified sites"),
	})
	dlg.splitTunnelingModeCombo.CurrentIndexChanged().Attach(dlg.onSplitTunnelingModeChanged)
	
	splitSitesLabel, _ := walk.NewTextLabel(dlg.splitTunnelingGroup)
	splitSitesLabel.SetText(l18n.Sprintf("&Sites:"))
	splitLayout.SetRange(splitSitesLabel, walk.Rectangle{0, 1, 1, 1})
	if dlg.splitTunnelingSitesEdit, err = walk.NewLineEdit(dlg.splitTunnelingGroup); err != nil {
		return nil, err
	}
	splitLayout.SetRange(dlg.splitTunnelingSitesEdit, walk.Rectangle{1, 1, 1, 1})
	dlg.splitTunnelingSitesEdit.SetToolTipText(l18n.Sprintf("Comma-separated list of IP addresses or domains"))
	dlg.splitTunnelingSitesEdit.TextChanged().Attach(dlg.onSplitTunnelingSitesChanged)
	
	if dlg.syntaxEdit, err = syntax.NewSyntaxEdit(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.syntaxEdit, walk.Rectangle{0, 4, 2, 1})

	buttonsContainer, err := walk.NewComposite(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(buttonsContainer, walk.Rectangle{0, 5, 2, 1})
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	if dlg.blockUntunneledTrafficCB, err = walk.NewCheckBox(buttonsContainer); err != nil {
		return nil, err
	}
	dlg.blockUntunneledTrafficCB.SetText(l18n.Sprintf("&Block untunneled traffic (kill-switch)"))
	dlg.blockUntunneledTrafficCB.SetToolTipText(l18n.Sprintf("When a configuration has exactly one peer, and that peer has an allowed IPs containing at least one of 0.0.0.0/0 or ::/0, and the interface does not have table off, then the tunnel service engages a firewall ruleset to block all traffic that is neither to nor from the tunnel interface or is to the wrong DNS server, with special exceptions for DHCP and NDP."))
	dlg.blockUntunneledTrafficCB.SetVisible(false)
	dlg.blockUntunneledTrafficCB.CheckedChanged().Attach(dlg.onBlockUntunneledTrafficCBCheckedChanged)

	walk.NewHSpacer(buttonsContainer)

	if dlg.saveButton, err = walk.NewPushButton(buttonsContainer); err != nil {
		return nil, err
	}
	dlg.saveButton.SetText(l18n.Sprintf("&Save"))
	dlg.saveButton.Clicked().Attach(dlg.onSaveButtonClicked)

	cancelButton, err := walk.NewPushButton(buttonsContainer)
	if err != nil {
		return nil, err
	}
	cancelButton.SetText(l18n.Sprintf("Cancel"))
	cancelButton.Clicked().Attach(dlg.Cancel)

	dlg.SetCancelButton(cancelButton)
	dlg.SetDefaultButton(dlg.saveButton)

	dlg.syntaxEdit.TextChanged().Attach(dlg.onSyntaxEditTextChanged)
	dlg.syntaxEdit.PrivateKeyChanged().Attach(dlg.onSyntaxEditPrivateKeyChanged)
	dlg.syntaxEdit.BlockUntunneledTrafficStateChanged().Attach(dlg.onBlockUntunneledTrafficStateChanged)
	dlg.syntaxEdit.SetText(dlg.config.ToWgQuick())
	
	// Parse initial config and populate UI controls
	dlg.updateControlsFromConfig()

	// Insert a dummy label immediately preceding syntaxEdit to have screen readers read it.
	// Otherwise they fallback to "RichEdit Control".
	syntaxEditWnd := dlg.syntaxEdit.Handle()
	parentWnd := win.GetParent(syntaxEditWnd)
	labelWnd := win.CreateWindowEx(0,
		windows.StringToUTF16Ptr("STATIC"), windows.StringToUTF16Ptr(l18n.Sprintf("&Configuration:")),
		win.WS_CHILD|win.WS_GROUP|win.SS_LEFT, 0, 0, 0, 0,
		parentWnd, win.HMENU(^uintptr(0)), win.HINSTANCE(win.GetWindowLongPtr(parentWnd, win.GWLP_HINSTANCE)), nil)
	prevWnd := win.GetWindow(syntaxEditWnd, win.GW_HWNDPREV)
	nextWnd := win.GetWindow(syntaxEditWnd, win.GW_HWNDNEXT)
	win.SetWindowPos(labelWnd, prevWnd, 0, 0, 0, 0, win.SWP_NOSIZE|win.SWP_NOMOVE)
	win.SetWindowPos(syntaxEditWnd, labelWnd, 0, 0, 0, 0, win.SWP_NOSIZE|win.SWP_NOMOVE)
	win.SetWindowPos(nextWnd, syntaxEditWnd, 0, 0, 0, 0, win.SWP_NOSIZE|win.SWP_NOMOVE)

	if tunnel != nil {
		dlg.Starting().Attach(func() {
			dlg.syntaxEdit.SetFocus()
		})
	}

	disposables.Spare()

	return dlg, nil
}

func equalIPCidrs(a, b conf.IPCidr) bool {
	return a.IP.Equal(b.IP) && (a.Cidr == b.Cidr)
}

func (dlg *EditDialog) onBlockUntunneledTrafficCBCheckedChanged() {
	if dlg.blockUntunneledTraficCheckGuard {
		return
	}
	var (
		v400    = conf.IPCidr{IP: net.IPv4zero, Cidr: 0}
		v600000 = conf.IPCidr{IP: net.IPv6zero, Cidr: 0}
		v401    = conf.IPCidr{IP: net.IPv4zero, Cidr: 1}
		v600001 = conf.IPCidr{IP: net.IPv6zero, Cidr: 1}
		v41281  = conf.IPCidr{IP: net.IPv4(0x80, 0, 0, 0), Cidr: 1}
		v680001 = conf.IPCidr{IP: net.IP{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Cidr: 1}
	)

	block := dlg.blockUntunneledTrafficCB.Checked()
	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), "temporary")
	var newAllowedIPs []conf.IPCidr

	if err != nil {
		goto err
	}
	if len(cfg.Peers) != 1 {
		goto err
	}

	newAllowedIPs = make([]conf.IPCidr, 0, len(cfg.Peers[0].AllowedIPs))
	if block {
		var (
			foundV401    bool
			foundV41281  bool
			foundV600001 bool
			foundV680001 bool
		)
		for _, allowedip := range cfg.Peers[0].AllowedIPs {
			if equalIPCidrs(allowedip, v600001) {
				foundV600001 = true
			} else if equalIPCidrs(allowedip, v680001) {
				foundV680001 = true
			} else if equalIPCidrs(allowedip, v401) {
				foundV401 = true
			} else if equalIPCidrs(allowedip, v41281) {
				foundV41281 = true
			} else {
				newAllowedIPs = append(newAllowedIPs, allowedip)
			}
		}
		if !((foundV401 && foundV41281) || (foundV600001 && foundV680001)) {
			goto err
		}
		if foundV401 && foundV41281 {
			newAllowedIPs = append(newAllowedIPs, v400)
		} else if foundV401 {
			newAllowedIPs = append(newAllowedIPs, v401)
		} else if foundV41281 {
			newAllowedIPs = append(newAllowedIPs, v41281)
		}
		if foundV600001 && foundV680001 {
			newAllowedIPs = append(newAllowedIPs, v600000)
		} else if foundV600001 {
			newAllowedIPs = append(newAllowedIPs, v600001)
		} else if foundV680001 {
			newAllowedIPs = append(newAllowedIPs, v680001)
		}
		cfg.Peers[0].AllowedIPs = newAllowedIPs
	} else {
		var (
			foundV400    bool
			foundV600000 bool
		)
		for _, allowedip := range cfg.Peers[0].AllowedIPs {
			if equalIPCidrs(allowedip, v600000) {
				foundV600000 = true
			} else if equalIPCidrs(allowedip, v400) {
				foundV400 = true
			} else {
				newAllowedIPs = append(newAllowedIPs, allowedip)
			}
		}
		if !(foundV400 || foundV600000) {
			goto err
		}
		if foundV400 {
			newAllowedIPs = append(newAllowedIPs, v401)
			newAllowedIPs = append(newAllowedIPs, v41281)
		}
		if foundV600000 {
			newAllowedIPs = append(newAllowedIPs, v600001)
			newAllowedIPs = append(newAllowedIPs, v680001)
		}
		cfg.Peers[0].AllowedIPs = newAllowedIPs
	}
	dlg.syntaxEdit.SetText(cfg.ToWgQuick())
	return

err:
	text := dlg.syntaxEdit.Text()
	dlg.syntaxEdit.SetText("")
	dlg.syntaxEdit.SetText(text)
}

func (dlg *EditDialog) onBlockUntunneledTrafficStateChanged(state int) {
	dlg.blockUntunneledTraficCheckGuard = true
	switch syntax.BlockState(state) {
	case syntax.InevaluableBlockingUntunneledTraffic:
		dlg.blockUntunneledTrafficCB.SetVisible(false)
	case syntax.BlockingUntunneledTraffic:
		dlg.blockUntunneledTrafficCB.SetVisible(true)
		dlg.blockUntunneledTrafficCB.SetChecked(true)
	case syntax.NotBlockingUntunneledTraffic:
		dlg.blockUntunneledTrafficCB.SetVisible(true)
		dlg.blockUntunneledTrafficCB.SetChecked(false)
	}
	dlg.blockUntunneledTraficCheckGuard = false
}

func (dlg *EditDialog) onSyntaxEditPrivateKeyChanged(privateKey string) {
	if privateKey == dlg.lastPrivateKey {
		return
	}
	dlg.lastPrivateKey = privateKey
	key, _ := conf.NewPrivateKeyFromString(privateKey)
	if key != nil {
		dlg.pubkeyEdit.SetText(key.Public().String())
	} else {
		dlg.pubkeyEdit.SetText(l18n.Sprintf("(unknown)"))
	}
}

func (dlg *EditDialog) onSyntaxEditTextChanged() {
	dlg.saveButton.SetEnabled(dlg.syntaxEdit.HaveErrors())
	// Update controls from text when user edits directly
	if !dlg.updatingFromText {
		dlg.updateControlsFromConfig()
	}
}

func (dlg *EditDialog) onSaveButtonClicked() {
	newName := dlg.nameEdit.Text()
	if newName == "" {
		showWarningCustom(dlg, l18n.Sprintf("Invalid name"), l18n.Sprintf("A name is required."))
		return
	}
	if !conf.TunnelNameIsValid(newName) {
		showWarningCustom(dlg, l18n.Sprintf("Invalid name"), l18n.Sprintf("Tunnel name ‘%s’ is invalid.", newName))
		return
	}
	newNameLower := strings.ToLower(newName)

	if newNameLower != strings.ToLower(dlg.config.Name) {
		existingTunnelList, err := manager.IPCClientTunnels()
		if err != nil {
			showWarningCustom(dlg, l18n.Sprintf("Unable to list existing tunnels"), err.Error())
			return
		}
		for _, tunnel := range existingTunnelList {
			if strings.ToLower(tunnel.Name) == newNameLower {
				showWarningCustom(dlg, l18n.Sprintf("Tunnel already exists"), l18n.Sprintf("Another tunnel already exists with the name ‘%s’.", newName))
				return
			}
		}
	}

	// Update config text from UI controls before parsing
	dlg.updateConfigTextFromControls()

	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), newName)
	if err != nil {
		showErrorCustom(dlg, l18n.Sprintf("Unable to create new configuration"), err.Error())
		return
	}

	dlg.config = *cfg
	dlg.Accept()
}

func (dlg *EditDialog) updateControlsFromConfig() {
	dlg.updatingFromText = true
	defer func() { dlg.updatingFromText = false }()
	
	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), "temporary")
	if err != nil {
		// If parsing fails, clear controls
		dlg.tlsPipeEnabledCB.SetChecked(false)
		dlg.tlsPipePasswordEdit.SetText("")
		dlg.tlsPipeServerNameEdit.SetText("")
		dlg.tlsPipeSecureCB.SetChecked(false)
		dlg.tlsPipeProxyEdit.SetText("")
		dlg.tlsPipeFingerprintCombo.SetCurrentIndex(0)
		dlg.updateTlsPipeControlsVisibility(false)
		dlg.splitTunnelingModeCombo.SetCurrentIndex(0)
		dlg.splitTunnelingSitesEdit.SetText("")
		return
	}
	
	// Update TLS Pipe controls from first peer
	if len(cfg.Peers) > 0 && cfg.Peers[0].UdpTlsPipe != nil && cfg.Peers[0].UdpTlsPipe.Enabled {
		udpTlsPipe := cfg.Peers[0].UdpTlsPipe
		dlg.tlsPipeEnabledCB.SetChecked(true)
		dlg.tlsPipePasswordEdit.SetText(udpTlsPipe.Password)
		dlg.tlsPipeServerNameEdit.SetText(udpTlsPipe.TlsServerName)
		dlg.tlsPipeSecureCB.SetChecked(udpTlsPipe.Secure)
		dlg.tlsPipeProxyEdit.SetText(udpTlsPipe.Proxy)
		if udpTlsPipe.FingerprintProfile != "" {
			dlg.tlsPipeFingerprintCombo.SetText(udpTlsPipe.FingerprintProfile)
		} else {
			dlg.tlsPipeFingerprintCombo.SetCurrentIndex(0)
		}
		dlg.updateTlsPipeControlsVisibility(true)
	} else {
		dlg.tlsPipeEnabledCB.SetChecked(false)
		dlg.tlsPipePasswordEdit.SetText("")
		dlg.tlsPipeServerNameEdit.SetText("")
		dlg.tlsPipeSecureCB.SetChecked(false)
		dlg.tlsPipeProxyEdit.SetText("")
		dlg.tlsPipeFingerprintCombo.SetCurrentIndex(0)
		dlg.updateTlsPipeControlsVisibility(false)
	}
	
	// Update Split Tunneling controls from interface
	if cfg.Interface.SplitTunneling != nil && cfg.Interface.SplitTunneling.Mode != conf.SplitModeAllSites {
		splitTunneling := cfg.Interface.SplitTunneling
		switch splitTunneling.Mode {
		case conf.SplitModeAllSites:
			dlg.splitTunnelingModeCombo.SetCurrentIndex(0)
		case conf.SplitModeOnlyForwardSites:
			dlg.splitTunnelingModeCombo.SetCurrentIndex(1)
		case conf.SplitModeAllExceptSites:
			dlg.splitTunnelingModeCombo.SetCurrentIndex(2)
		}
		dlg.splitTunnelingSitesEdit.SetText(strings.Join(splitTunneling.Sites, ", "))
	} else {
		dlg.splitTunnelingModeCombo.SetCurrentIndex(0)
		dlg.splitTunnelingSitesEdit.SetText("")
	}
}

func (dlg *EditDialog) updateConfigTextFromControls() {
	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), "temporary")
	if err != nil {
		// If parsing fails, we can't update - user needs to fix the text first
		return
	}
	
	// Update TLS Pipe config for first peer (create peer if needed)
	if dlg.tlsPipeEnabledCB.Checked() {
		if len(cfg.Peers) == 0 {
			// Need at least one peer for TLS pipe
			return
		}
		if cfg.Peers[0].UdpTlsPipe == nil {
			cfg.Peers[0].UdpTlsPipe = &conf.UdpTlsPipeConfig{}
		}
		cfg.Peers[0].UdpTlsPipe.Enabled = true
		cfg.Peers[0].UdpTlsPipe.Password = dlg.tlsPipePasswordEdit.Text()
		cfg.Peers[0].UdpTlsPipe.TlsServerName = dlg.tlsPipeServerNameEdit.Text()
		cfg.Peers[0].UdpTlsPipe.Secure = dlg.tlsPipeSecureCB.Checked()
		cfg.Peers[0].UdpTlsPipe.Proxy = dlg.tlsPipeProxyEdit.Text()
		fingerprintText := dlg.tlsPipeFingerprintCombo.Text()
		if fingerprintText != "" {
			cfg.Peers[0].UdpTlsPipe.FingerprintProfile = fingerprintText
		} else {
			cfg.Peers[0].UdpTlsPipe.FingerprintProfile = ""
		}
	} else if len(cfg.Peers) > 0 {
		cfg.Peers[0].UdpTlsPipe = nil
	}
	
	// Update Split Tunneling config for interface
	modeIndex := dlg.splitTunnelingModeCombo.CurrentIndex()
	sitesText := strings.TrimSpace(dlg.splitTunnelingSitesEdit.Text())
	
	if modeIndex == 0 && sitesText == "" {
		cfg.Interface.SplitTunneling = nil
	} else {
		if cfg.Interface.SplitTunneling == nil {
			cfg.Interface.SplitTunneling = &conf.SplitTunnelingConfig{}
		}
		switch modeIndex {
		case 0:
			cfg.Interface.SplitTunneling.Mode = conf.SplitModeAllSites
		case 1:
			cfg.Interface.SplitTunneling.Mode = conf.SplitModeOnlyForwardSites
		case 2:
			cfg.Interface.SplitTunneling.Mode = conf.SplitModeAllExceptSites
		}
		if sitesText != "" {
			sites := strings.Split(sitesText, ",")
			cfg.Interface.SplitTunneling.Sites = make([]string, 0, len(sites))
			for _, site := range sites {
				site = strings.TrimSpace(site)
				if site != "" {
					cfg.Interface.SplitTunneling.Sites = append(cfg.Interface.SplitTunneling.Sites, site)
				}
			}
		} else {
			cfg.Interface.SplitTunneling.Sites = nil
		}
	}
	
	dlg.updatingFromText = true
	dlg.syntaxEdit.SetText(cfg.ToWgQuick())
	dlg.updatingFromText = false
}

func (dlg *EditDialog) updateTlsPipeControlsVisibility(enabled bool) {
	dlg.tlsPipePasswordEdit.SetEnabled(enabled)
	dlg.tlsPipeServerNameEdit.SetEnabled(enabled)
	dlg.tlsPipeSecureCB.SetEnabled(enabled)
	dlg.tlsPipeProxyEdit.SetEnabled(enabled)
	dlg.tlsPipeFingerprintCombo.SetEnabled(enabled)
}

func (dlg *EditDialog) onTlsPipeEnabledChanged() {
	enabled := dlg.tlsPipeEnabledCB.Checked()
	dlg.updateTlsPipeControlsVisibility(enabled)
	if !dlg.updatingFromText {
		dlg.updateConfigTextFromControls()
	}
}

func (dlg *EditDialog) onTlsPipeFieldChanged() {
	if !dlg.updatingFromText {
		dlg.updateConfigTextFromControls()
	}
}

func (dlg *EditDialog) onSplitTunnelingModeChanged() {
	if !dlg.updatingFromText {
		dlg.updateConfigTextFromControls()
	}
}

func (dlg *EditDialog) onSplitTunnelingSitesChanged() {
	if !dlg.updatingFromText {
		dlg.updateConfigTextFromControls()
	}
}

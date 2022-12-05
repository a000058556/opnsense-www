<?php

/*
 * Copyright (C) 2014-2016 Deciso B.V.
 * Copyright (C) 2010 Ermal Luçi
 * Copyright (C) 2003-2004 Justin Ellison <justin@techadvise.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

require_once("guiconfig.inc");
require_once("interfaces.inc");

if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    $rely_pconfig['enable'] = isset($config['dhcrelay']['enable']);
    // 若沒有$config['dhcrelay']['interface']) ， $rely_pconfig['enable'] = array();
    if (empty($config['dhcrelay']['interface'])) {
        $rely_pconfig['interface'] = array();
    } else {
        $rely_pconfig['interface'] = explode(",", $config['dhcrelay']['interface']);
    }
    // 若沒有$config['dhcrelay']['server']) ， $rely_pconfig['server'] = "";
    if (empty($config['dhcrelay']['server'])) {
        $rely_pconfig['server'] = "";
    } else {
        $rely_pconfig['server'] = $config['dhcrelay']['server'];
    }
    $rely_pconfig['agentoption'] = isset($config['dhcrelay']['agentoption']);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_errors = array();
    $rely_pconfig = $_POST;

    /* input validation */
    $reqdfields = explode(" ", "server interface");
    $reqdfieldsn = array(gettext("Destination Server"), gettext("Interface"));

    do_input_validation($rely_pconfig, $reqdfields, $reqdfieldsn, $input_errors);

    if (!empty($rely_pconfig['server'])) {
        $checksrv = explode(",", $rely_pconfig['server']);
        foreach ($checksrv as $srv) {
            if (!is_ipaddr($srv)) {
                $input_errors[] = gettext("A valid Destination Server IP address must be specified.");
            }
        }
    }

    // 當沒有輸入錯誤時，將post收到的資料寫入config中
    if (count($input_errors) == 0) {
        if (empty($config['dhcrelay'])) {
            $config['dhcrelay'] =  array();
        }
        $config['dhcrelay']['enable'] = !empty($rely_pconfig['enable']);
        $config['dhcrelay']['interface'] = implode(",", $rely_pconfig['interface']);
        $config['dhcrelay']['agentoption'] = !empty($rely_pconfig['agentoption']);
        $config['dhcrelay']['server'] = $rely_pconfig['server'];
        write_config();
        plugins_configure('dhcrelay', false, array('inet'));
        header(url_safe('Location: /services_dhcp_relay.php'));
        exit;
    }
}


$iflist = get_configured_interface_with_descr();

/*   set the enabled flag which will tell us if DHCP server is enabled
 *   on any interface.   We will use this to disable dhcp-relay since
 *   the two are not compatible with each other.
 */
$dhcpd_enabled = false;
if (is_array($config['dhcpd'])) {
    foreach($config['dhcpd'] as $intf => $dhcp) {
        if (isset($dhcp['enable']) && !empty($config['interfaces'][$intf]['enable'])) {
            $dhcpd_enabled = true;
        }
    }
}
$service_hook = 'dhcrelay';
include("head.inc");
?>

<body>
<?php include("fbegin.inc"); ?>
  <section class="page-content-main">
    <div class="container-fluid">
      <div class="row">
<?php
      if ($dhcpd_enabled) {
        print_info_box(gettext('DHCP Server is currently enabled. Cannot enable the DHCP Relay service while the DHCP Server is enabled on any interface.'));
      } else {
?>
        <?php if (isset($input_errors) && count($input_errors) > 0) print_input_errors($input_errors); ?>
        <?php if (isset($savemsg)) print_info_box($savemsg); ?>
        <section class="col-xs-12">
          <div class="content-box">
            <!-- 上方DHCP Server(v4)選單 -->
            <ul class="nav nav-tabs" id="maintabs">
              <li><a id="interfaces_tab" href="/interfaces.php?if=<?=$if; ?>"><?=gettext("Interfaces(".$if.")"); ?></a></li>
              <li class="active"><a id="relayv4_tab" href="/services_dhcp_relay.php"><?=gettext("Relay(v4)"); ?></a></li>
            </ul>
            <form method="post" name="iform" id="iform">
              <div>
                <div class="table-responsive">
                  <table class="table table-striped opnsense_standard_table_form">
                    <tr>
                      <td style="width:22%"><strong><?=gettext("DHCP Relay configuration"); ?></strong></td>
                      <td style="width:78%; text-align:right">
                        <small><?=gettext("full help"); ?> </small>
                        <i class="fa fa-toggle-off text-danger"  style="cursor: pointer;" id="show_all_help_page"></i>
                      </td>
                    </tr>
                    <tr>
                      <td><i class="fa fa-info-circle text-muted"></i> <?=gettext('Enable') ?></td>
                      <td>
                        <input name="enable" type="checkbox" value="yes" <?=!empty($rely_pconfig['enable']) ? "checked=\"checked\"" : ""; ?> onclick="enable_change(false)" />
                      </td>
                    </tr>
                    <tr>
                      <td><a id="help_for_interface" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Interface(s)') ?></td>
                      <td>
                        <select id="interface" name="interface[]" multiple="multiple" class="selectpicker">
<?php
                        foreach ($iflist as $ifent => $ifdesc):
                        if (!is_ipaddr(get_interface_ip($ifent))) {
                            continue;
                        }?>
                          <option value="<?=$ifent;?>" <?=isset($rely_pconfig['interface']) && in_array($ifent, $rely_pconfig['interface']) ? "selected=\"selected\"" : "";?>>
                            <?=$ifdesc;?>
                          </option>
<?php
                        endforeach;?>
                        </select>
                        <div class="hidden" data-for="help_for_interface">
                          <?= gettext('Interfaces without an IP address will not be shown.') ?>
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <td><a id="help_for_agentoption" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("Append circuit ID");?></td>
                      <td>
                          <input name="agentoption" type="checkbox" value="yes" <?=!empty($rely_pconfig['agentoption']) ? "checked=\"checked\"" : ""; ?> />
                          <strong><?=gettext("Append circuit ID and agent ID to requests"); ?></strong><br />
                          <div class="hidden" data-for="help_for_agentoption">
                            <?= gettext('If this is checked, the DHCP relay will append the circuit ID (interface number) and the agent ID to the DHCP request.') ?>
                          </div>
                      </td>
                    </tr>
                    <tr>
                      <td><a id="help_for_server" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("Destination servers");?></td>
                      <td>
                        <input name="server" type="text" value="<?=!empty($rely_pconfig['server']) ? htmlspecialchars($rely_pconfig['server']):"";?>" />
                        <div class="hidden" data-for="help_for_server">
                          <?=gettext("These are the IP addresses of servers to which DHCP requests are relayed. You can enter multiple server IP addresses, separated by commas.");?>
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <td>&nbsp;</td>
                      <td>
                        <input name="Submit" type="submit" class="btn btn-primary" value="<?=html_safe(gettext('Save'));?>" onclick="enable_change(true)" />
                      </td>
                    </tr>
                  </table>
                </div>
              </div>
            </form>
          </div>
        </section>
        <?php } ?>
      </div>
    </div>
  </section>
<?php include("foot.inc"); ?>

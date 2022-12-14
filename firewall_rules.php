<?php

/*
 * Copyright (C) 2014-2015 Deciso B.V.
 * Copyright (C) 2005 Scott Ullrich <sullrich@gmail.com>
 * Copyright (C) 2003-2004 Manuel Kasper <mk@neon1.net>
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
require_once("filter.inc");
require_once("system.inc");

/***********************************************************************************************************
 * format functions for this page
 ***********************************************************************************************************/
function firewall_rule_item_proto($filterent)
{
    // construct line ipprotocol
    if (isset($filterent['ipprotocol'])) {
        switch($filterent['ipprotocol']) {
            case "inet":
                $record_ipprotocol = "IPv4 ";
                break;
            case "inet6":
                $record_ipprotocol = "IPv6 ";
                break;
            case "inet46":
                $record_ipprotocol = "IPv4+6 ";
                break;
        }
    } else {
        // when ipprotocol is not set, pf would normally figure out the ip proto itself.
        // reconstruct ipproto depending on source/destination address.
        if (!empty($filterent['from']) && is_ipaddr(explode("/", $filterent['from'])[0])) {
            // is_ipaddr() ???util.inc??????
            // strpos($filterent['from'], ":")????????? ":"???????????????????????? ??? false=?????????($filterent['from']???
            // ????????????":"     $record_ipprotocol = "IPv4 "
            // ???":"    $record_ipprotocol = "IPv6 "
            $record_ipprotocol = strpos($filterent['from'], ":") === false ? "IPv4 " :  "IPv6 ";
          // ???$filterent['to'] ?????? $record_ipprotocol 
        } elseif (!empty($filterent['to']) && is_ipaddr(explode("/", $filterent['to'])[0])) {
            $record_ipprotocol = strpos($filterent['to'], ":") === false ? "IPv4 " :  "IPv6 ";
          // ???$filterent['source']['address'] ?????? $record_ipprotocol 
        } elseif (isset($filterent['source']['address'])
                    && is_ipaddr(explode("/", $filterent['source']['address'])[0])) {
            $record_ipprotocol = strpos($filterent['source']['address'], ":") === false ? "IPv4 " : "IPv6 ";
          // ???$filterent['destination']['address'] ?????? $record_ipprotocol 
        } elseif (isset($filterent['destination']['address'])
                    && is_ipaddr(explode("/", $filterent['destination']['address'])[0])) {
            $record_ipprotocol = strpos($filterent['destination']['address'], ":") === false ? "IPv4 " : "IPv6 ";
        } else {
            $record_ipprotocol = "IPv4+6 ";
        }
    }
    // ICMP ??????(ICMP ???????????? : http://www.tsnien.idv.tw/Internet_WebBook/chap5/5-4%20ICMP%20%E9%80%9A%E8%A8%8A%E5%8D%94%E5%AE%9A.html)
    // Internet????????????????????????????????????????????????Internet Control Message Protocol, ICMP???????????????????????????????????????????????????
    // Ping?????????ICMP???Echo Request???Echo Reply??????????????????

    // ICMP ????????????:
    $icmptypes = array(
      "" => gettext("any"),
      "echoreq" => gettext("Echo Request"), // ????????????
      "echorep" => gettext("Echo Reply"),   // ????????????
      "unreach" => gettext("Destination Unreachable"), // ?????????????????????
      "squench" => gettext("Source Quench (Deprecated)"), // ????????????(?????????)
      "redir" => gettext("Redirect"), // ??????????????????
      "althost" => gettext("Alternate Host Address (Deprecated)"), // ??????????????????(?????????)
      "routeradv" => gettext("Router Advertisement"), // ???????????????
      "routersol" => gettext("Router Solicitation"), // ???????????????
      "timex" => gettext("Time Exceeded"), // ????????????
      "paramprob" => gettext("Parameter Problem"), // ????????????
      "timereq" => gettext("Timestamp"), // ??????????????????
      "timerep" => gettext("Timestamp Reply"), // ??????????????????
      "inforeq" => gettext("Information Request (Deprecated)"), // ????????????(?????????)
      "inforep" => gettext("Information Reply (Deprecated)"), // ????????????(?????????)
      "maskreq" => gettext("Address Mask Request (Deprecated)"), // ??????????????????(?????????)
      "maskrep" => gettext("Address Mask Reply (Deprecated)")// ??????????????????(?????????)
    );
    // ICMPv6 ????????????:
    $icmp6types = array(
      "" => gettext("any"),
      "unreach" => gettext("Destination unreachable"), // ?????????????????????
      "toobig" => gettext("Packet too big"), // ???????????????
      "timex" => gettext("Time exceeded"), // ????????????
      "paramprob" => gettext("Invalid IPv6 header"), // ????????? IPv6 ??????
      "echoreq" => gettext("Echo service request"), // ????????????
      "echorep" => gettext("Echo service reply"), // ????????????
      "groupqry" => gettext("Group membership query"), // ??????????????????
      "listqry" => gettext("Multicast listener query"), // ???????????????
      "grouprep" => gettext("Group membership report"),// ????????????????????????
      "listenrep" => gettext("Multicast listener report"), // ???????????????
      "groupterm" => gettext("Group membership termination"), // ????????????????????????
      "listendone" => gettext("Multicast listener done"), // ?????????????????????
      "routersol" => gettext("Router solicitation"), // ???????????????
      "routeradv" => gettext("Router advertisement"), // ???????????????
      "neighbrsol" => gettext("Neighbor solicitation"), // ????????????
      "neighbradv" => gettext("Neighbor advertisement"), // ????????????
      "redir" => gettext("Shorter route exists"), // ?????????????????????
      "routrrenum" => gettext("Route renumbering"), // ??????????????????
      "fqdnreq" => gettext("FQDN query"), // ?????????????????? FQDN???Fully Qualified Domain Name?????????
      "niqry" => gettext("Node information query"), // ??????????????????
      "wrureq" => gettext("Who-are-you request"), // ???????????????
      "fqdnrep" => gettext("FQDN reply"), // ???????????? FQDN???Fully Qualified Domain Name?????????
      "nirep" => gettext("Node information reply"), // ??????????????????
      "wrurep" => gettext("Who-are-you reply"), // ???????????????
      "mtraceresp" => gettext("mtrace response"), // ????????????
      "mtrace" => gettext("mtrace messages") // ????????????
    );
    // ???$filterent['protocol']?????????&& == "icmp" && !empty($filterent['icmptype'])
    if (isset($filterent['protocol']) && $filterent['protocol'] == "icmp" && !empty($filterent['icmptype'])) {
        $result = $record_ipprotocol;
        // html_safe()?????????guiconfig.inc
        // strtoupper()???????????????????????????
        $result .= sprintf(
          "<span data-toggle=\"tooltip\" title=\"ICMP type: %s \"> %s </span>",
          html_safe($icmptypes[$filterent['icmptype']]),
          isset($filterent['protocol']) ? strtoupper($filterent['protocol']) : "*"
        );
        return $result;
    // ???$filterent['protocol']????????? && !empty($filterent['icmp6-type'])
    } elseif (isset($filterent['protocol']) && !empty($filterent['icmp6-type'])) {
        $result = $record_ipprotocol;
        $result .= sprintf(
          "<span data-toggle=\"tooltip\" title=\"ICMP6 type: %s \"> %s </span>",
          html_safe($icmp6types[$filterent['icmp6-type']]),
          isset($filterent['protocol']) ? strtoupper($filterent['protocol']) : "*"
        );
        return $result;
    } else {
        return $record_ipprotocol . (isset($filterent['protocol']) ? strtoupper($filterent['protocol']) : "*");
    }
}


function firewall_rule_item_icons($filterent)
{
    $result = "";
    // ???$filterent['direction']????????? or $filterent['direction'] == "in"
    if (empty($filterent['direction']) || $filterent['direction'] == "in") {
        // $result = <i class="fa fa-long-arrow-right fa-fw text-info" data-toggle="tooltip" title="in"></i>
        $result .= sprintf(
            "<i class=\"fa fa-long-arrow-right fa-fw text-info\" data-toggle=\"tooltip\" title=\"%s\"></i>",
            gettext("in")
        );
    // ???$filterent['direction']???????????? and $filterent['direction'] == "out"
    } elseif (!empty($filterent['direction']) && $filterent['direction'] == "out") {
        // $result = <i class="fa fa-long-arrow-left fa-fw" data-toggle="tooltip" title="out"></i>
        $result .= sprintf(
            "<i class=\"fa fa-long-arrow-left fa-fw\" data-toggle=\"tooltip\" title=\"%s\"></i>",
            gettext("out")
        );
    } else {
        // $result = <i class="fa fa-exchange fa-fw" data-toggle="tooltip" title="any"></i>
        $result .= sprintf(
            "<i class=\"fa fa-exchange fa-fw\" data-toggle=\"tooltip\" title=\"%s\"></i>",
            gettext("any")
        );
    }
    // ???$filterent['floating']????????? and $filterent['quick'] === null
    if (empty($filterent['floating']) && $filterent['quick'] === null){
        $is_quick = true;
    // ???$filterent['floating']???????????? and $filterent['quick'] === null
    } elseif (!empty($filterent['floating']) && $filterent['quick'] === null) {
        $is_quick = false;
    } else {
        $is_quick = $filterent['quick'];
    }

    if ($is_quick) {
        // <i class="fa fa-flash fa-fw text-warning" data-toggle="tooltip" title="first match"></i>
        $result .= sprintf(
            "<i class=\"fa fa-flash fa-fw text-warning\" data-toggle=\"tooltip\" title=\"%s\"></i>",
            gettext('first match')
        );
    } else {
      // <i class="fa fa-flash fa-fw text-muted" data-toggle="tooltip" title="last match"></i>
      $result .= sprintf(
          "<i class=\"fa fa-flash fa-fw text-muted\" data-toggle=\"tooltip\" title=\"%s\"></i>",
          gettext('last match')
      );
    }

    return $result;
}

function firewall_rule_item_action($filterent)
{
    // ???$filterent['type'] == "block" and $filterent['disabled']?????????
    if ($filterent['type'] == "block" && empty($filterent['disabled'])) {
        return "fa fa-times fa-fw text-danger";
    // ???$filterent['type'] == "block" and $filterent['disabled']????????????
    } elseif ($filterent['type'] == "block" && !empty($filterent['disabled'])) {
        return "fa fa-times fa-fw text-muted";
    // ???$filterent['type'] == "reject" and $filterent['disabled']?????????
    }  elseif ($filterent['type'] == "reject" && empty($filterent['disabled'])) {
        return "fa fa-times-circle fa-fw text-danger";
    // ???$filterent['type'] == "reject" and $filterent['disabled']?????????
    }  elseif ($filterent['type'] == "reject" && !empty($filterent['disabled'])) {
        return "fa fa-times-circle fa-fw text-muted";
    // ???$filterent['disabled']?????????
    } elseif (empty($filterent['disabled'])) {
        return "fa fa-play fa-fw text-success";
    } else {
        return "fa fa-play fa-fw text-muted";
    }
}

function firewall_rule_item_log($filterent)
{
    // ???$filterent['log'] == true
    if ($filterent['log'] == true) {
        return "fa fa-info-circle fa-fw text-info";
    } else {
        return "fa fa-info-circle fa-fw text-muted";
    }
}
/***********************************************************************************************************
 *
 ***********************************************************************************************************/

$a_filter = &config_read_array('filter', 'rule'); // ???????????????config_array??????

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_GET['if'])) {
        $current_if = htmlspecialchars($_GET['if']); // ??????????????????????????????
    } else {
        $current_if = "FloatingRules"; // ????????????
    }
    // ??????POST???????????????
    // ??????iform??????POST??????
    // <form action="firewall_rules.php?if=<?=$selected_if>;" method="post" name="iform" id="iform">
    // <input type="hidden" id="id" name="id" value="" />
    // <input type="hidden" id="action" name="act" value="" />
    $pconfig = $_POST;
    // ???$pconfig['id']?????????$a_filter[$pconfig['id']])????????????
    if (isset($pconfig['id']) && isset($a_filter[$pconfig['id']])) {
        // id found and valid
        $id = $pconfig['id'];
    }
    // ???$pconfig['act']?????????== "apply"???
    if (isset($pconfig['act']) && $pconfig['act'] == "apply") {
        system_cron_configure(); // ???system.inc??????
        filter_configure(); // ???filter.inc??????
        clear_subsystem_dirty('filter'); // ???util.inc??????
        $savemsg = get_std_save_message(); // ???guiconfig.inc??????
    // ???$pconfig['act']?????? ??? == "del" ?????????$id???
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'del' && isset($id)) {
        // delete single item
        // ???$a_filter[$id]['associated-rule-id'])????????????
        if (!empty($a_filter[$id]['associated-rule-id'])) {
            // unlink nat entry
            // ???$config['nat']['rule']?????????
            if (isset($config['nat']['rule'])) {
                // ??????config_array??????
                $a_nat = &config_read_array('nat', 'rule');
                foreach ($a_nat as &$natent) {
                    if ($natent['associated-rule-id'] == $a_filter[$id]['associated-rule-id']) {
                        $natent['associated-rule-id'] = ''; // ???????????????
                    }
                }
            }
        }
        unset($a_filter[$id]); // ??????????????????
        write_config(); // ???config.inc?????????????????????config
        mark_subsystem_dirty('filter');
        // ???util.inc???????????????????????????????????????????????????
        // function mark_subsystem_dirty($subsystem = '')
        // {
        //     // touch(filename, time, atime)  ??????????????????????????????????????????
        //     // filename ?????? ?????????????????? > "/tmp/{$subsystem}.dirty"
        //     // time ?????? ????????????(?????????????????????)
        //     // atime ?????? ??????????????????(?????????????????????)
        //     touch("/tmp/{$subsystem}.dirty");
        // }
        
        //  $current_if = htmlspecialchars($_GET['if']);
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
      // ???$pconfig['act']?????? and == "del_x" and ???$pconfig['rule'] and $pconfig['rule']????????????>0
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'del_x' && isset($pconfig['rule']) && count($pconfig['rule']) > 0) {
        // delete selected rules ?????????????????????rules
        foreach ($pconfig['rule'] as $rulei) {
            // unlink nat entry
            if (isset($config['nat']['rule'])) {
                $a_nat = &config_read_array('nat', 'rule');
                foreach ($a_nat as &$natent) {
                    if ($natent['associated-rule-id'] == $a_filter[$rulei]['associated-rule-id']) {
                        $natent['associated-rule-id'] = ''; // ??????rule?????????
                    }
                }
            }
            unset($a_filter[$rulei]); // ??????????????????rule
        }
        write_config();
        mark_subsystem_dirty('filter');
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
        // ???$pconfig['act']????????? and $pconfig['act']??????'toggle_enable', 'toggle_disable' and $pconfig['rule'])????????? and $pconfig['rule']??????????????????0
    } elseif (isset($pconfig['act']) && in_array($pconfig['act'], array('toggle_enable', 'toggle_disable')) && isset($pconfig['rule']) && count($pconfig['rule']) > 0) {
        foreach ($pconfig['rule'] as $rulei) { // ??????$pconfig['rule']
            // ???$a_filter[$rulei]['disabled']??????toggle_disable
            $a_filter[$rulei]['disabled'] = $pconfig['act'] == 'toggle_disable';
        }
        write_config();
        mark_subsystem_dirty('filter');
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
        // ???$pconfig['act']?????? ???== 'move'??? and ?????????$pconfig['rule']??????????????????0
    } elseif ( isset($pconfig['act']) && $pconfig['act'] == 'move' && isset($pconfig['rule']) && count($pconfig['rule']) > 0) {
        // move selected rules
        if (!isset($id)) { // ???????????????id???
            // if rule not set/found, move to end
            $id = count($a_filter); // id = ???????????????(????????????)
        }
        // ??????rule????????????legacy_bindings.inc??????legacy_move_config_list_items()
        $a_filter = legacy_move_config_list_items($a_filter, $id,  $pconfig['rule']);
        write_config();
        mark_subsystem_dirty('filter');
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
      // ???$pconfig['act']?????? ???== 'toggle' and $id?????????
      // ???????????? Rule ?????????
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'toggle' && isset($id)) {
        // toggle item
        // ???$a_filter[$id]['disabled']?????????
        if(isset($a_filter[$id]['disabled'])) {
            unset($a_filter[$id]['disabled']); // ??????['disabled']
        } else {
            $a_filter[$id]['disabled'] = true; // ??????['disabled']
        }
        write_config();
        mark_subsystem_dirty('filter');
        $response = array("id" => $id);
        // ?????????$a_filter[$id]['disabled']???$response["new_label"] = gettext("Disable Rule")
        // ??????$a_filter[$id]['disabled']???$response["new_label"] = gettext("Enable Rule")
        $response["new_label"] = !isset($a_filter[$id]['disabled']) ?  gettext("Disable Rule") : gettext("Enable Rule");
        // $response["new_state"] = true ??? false
        $response["new_state"] = !isset($a_filter[$id]['disabled']) ;
        echo json_encode($response);
        exit;
        // ??????log???????????????
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'log' && isset($id)) {
        // toggle logging
        if(isset($a_filter[$id]['log'])) {
            unset($a_filter[$id]['log']); // ??????['log']
        } else {
            $a_filter[$id]['log'] = true; // ??????['log']
        }
        write_config();
        mark_subsystem_dirty('filter');
        $response = array("id" => $id);
        $response["new_label"] = isset($a_filter[$id]['log']) ?  gettext("Disable Log") : gettext("Enable Log");
        $response["new_state"] = isset($a_filter[$id]['log']) ;
        echo json_encode($response);
        exit;
    }
}

$selected_if = 'FloatingRules'; // ????????????
if (isset($_GET['if'])) {  // ?????????????????????????????????
    $selected_if = htmlspecialchars($_GET['if']);
}

include("head.inc");

$a_filter_raw = config_read_array('filter', 'rule'); // ?????????config_array??????
legacy_html_escape_form_data($a_filter); // ??????array
?>
<body>
<script>
$( document ).ready(function() {
  // link delete buttons ?????????????????????????????????
  $(".act_delete").click(function(event){
    // .preventDefault();???????????????DOM?????????????????????<a>?????????????????????
    event.preventDefault();
    var id = $(this).attr("id").split('_').pop(-1); // ??????.attr("id")??????????????????id ??????.split('_')?????? ???????????????
    console.log(id);
    // ???id != 'x' ????????????????????????(??????id = del_4)
    if (id != 'x') {
      // delete single
      BootstrapDialog.show({ // ?????????????????????
        type:BootstrapDialog.TYPE_DANGER, // ??????:??????
        title: "<?= gettext("Rules");?>", // ??????
        message: "<?=gettext("Do you really want to delete this rule?");?>", // ??????
        // ???????????????
        buttons: [{
                  label: "<?= gettext("No");?>",
                  // dialogRef = ??????????????????
                  action: function(dialogRef) {
                      dialogRef.close(); // ????????????
                  }}, {
                  label: "<?= gettext("Yes");?>",
                  action: function(dialogRef) {
                    $("#id").val(id); // ????????????id = $pconfig['id']
                    $("#action").val("del"); // ?????? = $pconfig['act']
                    $("#iform").submit() // ?????????????????? = post????????????
                }
              }]
    });
    } else {
      // delete selected ??????????????????
      BootstrapDialog.show({
        type:BootstrapDialog.TYPE_DANGER,
        title: "<?= gettext("Rules");?>",
        message: "<?=gettext("Do you really want to delete the selected rules?");?>",
        buttons: [{
                  label: "<?= gettext("No");?>",
                  action: function(dialogRef) {
                      dialogRef.close();
                  }}, {
                  label: "<?= gettext("Yes");?>",
                  action: function(dialogRef) {
                    $("#id").val(""); // ????????????id
                    $("#action").val("del_x"); // ??????
                    $("#iform").submit() // ??????????????????
                }
              }]
      });
    }
  });

  // enable/disable selected ???????????????Rule ??????
  $(".act_toggle_enable").click(function(event){
    event.preventDefault();
    BootstrapDialog.show({
      type:BootstrapDialog.TYPE_DANGER,
      title: "<?= gettext("Rules");?>",
      message: "<?=gettext("Enable selected rules?");?>",
      buttons: [{
                label: "<?= gettext("No");?>",
                action: function(dialogRef) {
                    dialogRef.close();
                }}, {
                label: "<?= gettext("Yes");?>",
                action: function(dialogRef) {
                  $("#id").val("");
                  $("#action").val("toggle_enable"); // ?????? = $pconfig['act']
                  $("#iform").submit()
              }
            }]
    });
  });
  // ???????????????Rule ??????
  $(".act_toggle_disable").click(function(event){
    event.preventDefault();
    BootstrapDialog.show({
      type:BootstrapDialog.TYPE_DANGER,
      title: "<?= gettext("Rules");?>",
      message: "<?=gettext("Disable selected rules?");?>",
      buttons: [{
                label: "<?= gettext("No");?>",
                action: function(dialogRef) {
                    dialogRef.close();
                }}, {
                label: "<?= gettext("Yes");?>",
                action: function(dialogRef) {
                  $("#id").val("");
                  $("#action").val("toggle_disable"); // ?????? = $pconfig['act']
                  $("#iform").submit()
              }
            }]
    });
  });

  // link move buttons ?????????????????????????????????
  $(".act_move").click(function(event){
    event.preventDefault();
    var id = $(this).attr("id").split('_').pop(-1); // ??????id?????? : ????????????(move_6) ????????????id??????(move_4)
    $("#id").val(id);
    $("#action").val("move"); // ?????? = $pconfig['act']
    $("#iform").submit();
  });

  // link apply buttons ?????????????????????????????????
  $("#btn_apply").click(function(event){
    event.preventDefault();
    $("#action").val("apply"); // ?????? = $pconfig['act']
    $("#iform").submit();
  });

  // link toggle buttons ??????????????????/????????????
  $(".act_toggle").click(function(event){
      event.preventDefault();
      let target = $(this);
      target.addClass('fa-spinner fa-pulse'); // ??????loding?????? icon class????????????icon
      let id = target.attr("id").split('_').pop(-1); // id??????: toggle_5
      $.ajax("firewall_rules.php",{ // ??????ajax???post??????
          type: 'post',
          cache: false,
          dataType: "json",
          data: {'act': 'toggle', 'id': id}, // {'act': 'toggle'} = ($pconfig['act'] == 'toggle')
          // ?????????????????????
          success: function(response) {
              console.log(response);
              // ????????????response
              //{id: '2', new_label: 'Enable Rule', new_state: false}
              //{id: '2', new_label: 'Disable Rule', new_state: true}
              // .prop('title', response['new_label']) ?????????????????????????????????
              target.prop('title', response['new_label']).tooltip('fixTitle').tooltip('hide');
              target.removeClass('fa-spinner fa-pulse'); // ??????loding?????? icon
              // ???response['new_state'] = true
              if (response['new_state']) {
                  // ??????Class text-muted(?????????icon??????)????????????fa-play Class?????????text-success(?????????icon??????)??????????????????text-danger
                  target.removeClass('text-muted').addClass(target.hasClass('fa-play') ? 'text-success' : 'text-danger');
              } else { // ???response['new_state'] = false
                  // ??????Class text-success text-danger ?????????text-muted
                  target.removeClass('text-success text-danger').addClass('text-muted');
              }
              $("#fw-alert-box").removeClass("hidden"); // ??????????????????(apply)???hidden class
              $(".fw-alert-messages").addClass("hidden"); // ?????????????????????????????????
              $("#fw-alert-changes").removeClass("hidden"); // ??????????????????(apply)?????????hidden class
          },
          error: function () {
              // ??????????????????Class fa-spinner fa-pulse
              target.removeClass('fa-spinner fa-pulse');
          
          }
      });
  });

   // link log buttons ??????log??????/????????????
  $(".act_log").click(function(event){
      event.preventDefault();
      let target = $(this);
      // ???????????????icon ??? ??????loding?????? icon
      target.removeClass('fa-info-circle').addClass('fa-spinner fa-pulse');
      let id = target.attr("id").split('_').pop(-1);// id??????: toggle_2
      $.ajax("firewall_rules.php",{ // ??????ajax???post??????
          type: 'post',
          cache: false,
          dataType: "json",
          data: {'act': 'log', 'id': id}, // {'act': 'log'} = ($pconfig['act'] == 'log')
          success: function(response) {
              console.log("---------------????????????response---------------");
              console.log(response);
              // ????????????response
              // {id: '2', new_label: 'Enable Log', new_state: false}
              // {id: '2', new_label: 'Disable Log', new_state: true}
              // .prop('title', response['new_label']) ?????????????????????????????????
              target.prop('title', response['new_label']).tooltip('fixTitle').tooltip('hide');
              // ??????loding?????? icon ??? ??????log icon 
              target.removeClass('fa-spinner fa-pulse').addClass('fa-info-circle');
              // ???response['new_state'] = true
              if (response['new_state']) {
                  // ??????text-muted(?????????icon??????)?????????text-info(?????????icon??????)
                  target.removeClass('text-muted').addClass('text-info');
              } else { // ???response['new_state'] = false
                  // ??????text-info?????????text-muted
                  target.removeClass('text-info').addClass('text-muted');
              }
              $("#fw-alert-box").removeClass("hidden"); // ??????????????????(apply)???hidden class
              $(".fw-alert-messages").addClass("hidden"); // ?????????????????????????????????
              $("#fw-alert-changes").removeClass("hidden"); // ??????????????????(apply)?????????hidden class
          },
          error: function () {
              // ??????????????????Class fa-spinner fa-pulse ??????log icon 
              target.removeClass('fa-spinner fa-pulse').addClass('fa-info-circle');
          }
      });
  });

  // watch scroll position and set to last known on page load
  // ???/opnsense/www/js/opnsense.js ?????????
  // ???????????????????????????????????????????????????????????????????????????????????????
  watchScrollPosition();
  console.log("---------????????????????????????---------");
  console.log(window.location.href.replace(/\/|\:|\.|\?|\#/gi, ''));

  // select All ????????????????????????
  $("#selectAll").click(function(){
      // ??????????????????????????????:not(:disabled)
      // ??????"checked"???????????????????????????"checked"??????(??????????????????????????????????????????)
      $(".rule_select:not(:disabled)").prop("checked", $(this).prop("checked"));
  });

  // move category block
  // ????????????select category????????????
  // .detach()???.remove()??????????????????????????????????????????????????????????????????????????????.detach()??????????????????????????????
  // $('<p>??????????????????</p>').appendTo('.?????????);
  $("#category_block").detach().appendTo($(".page-content-head > .container-fluid > .list-inline"));
  console.log("-----.detach().appendTo-----");
  console.log($("#category_block").detach().appendTo($(".page-content-head > .container-fluid > .list-inline")));
  // ??????????????????pull-right??????????????????
  $("#category_block").addClass("pull-right"); 

  // ????????????(inspect)??????
  $("#btn_inspect").click(function(){
      // .data()??????  https://www.fooish.com/jquery/data.html
      // HTML5 ????????? data-key = '30' ??????????????? (data attributes)
      // ??????.data(key) = '30' ???????????????????????????
      // ?????? data attribute ????????? { ??? [ ?????????jQuery ???????????? JSON ???????????? JavaScript Object/Array
      // <<HTML>>
      // <div data-options='{"name":"John"}'></div>
      // <<jQuery>>
      // $('div').data('options').name === 'John';
      let mode = $(this).data('mode');
      console.log("-------------------mode-------------------");
      console.log(mode);
      // ??????data-mode = 'stats'
      if (mode === 'stats') {
            $(".view-stats").hide();
            $(".view-info").show();
            $(this).removeClass('active'); // ??????active
            // .data('mode', 'info') ??????????????????????????????????????????????????????
            $(this).data('mode', 'info'); // data-mode = 'info'
      } else { // ??????????????????????????????data-mode ???????????????mode =undefined
               // ?????????data-mode?????????????????????data-mode = 'stats'
            $(".view-stats").show();
            $(".view-info").hide();
            $(this).addClass('active'); // ??????active
            $(this).data('mode', 'stats'); // data-mode = 'stats'
            // ??????ajax?????? view-stats ?????????
            // api??????\opnsense\mvc\app\controllers\OPNsense\Firewall\Api\FilterUtilController.php > class FilterUtilController > function ruleStatsAction()
            $.ajax('api/firewall/filter_util/rule_stats', {
                success: function(response) {
                console.log("-------------------response-------------------");
                console.log(response); // {status: 'ok', stats: $result}
                    if (response.status == 'ok') {
                        let fileSizeTypes = ["", "K", "M", "G", "T", "P", "E", "Z", "Y"];
                        $.each(response.stats, function(index, value) {
                            console.log("----------------response.stats???index----------------");
                            console.log(index);
                            console.log("----------------response.stats???value----------------");
                            console.log(value);
                            // ???stats??????????????????index, value????????????????????????html????????? id ?????? ??????
                            // ????????????:
                            // index= 02f4bab031b57d1e30553ce08e0ec131
                            // value= {pf_rules: 2, evaluations: 36224, packets: 51, bytes: 5214, states: 0}
                            $("#" + index + "_evaluations").text(value.evaluations); // ???evaluations: 36224
                            $("#" + index + "_states").text(value.states); // ???states: 0
                            $("#" + index + "_packets").text(value.packets); // ???packets: 51
                            if (value.bytes > 0) { // ???bytes: 5214 > 0
                                // Math.floor(???):????????????????????????????????????
                                // Math.log()??????????????????????????????
                                // Math.log(value.bytes) / Math.log(1000)??????value.bytes?????????1000?????????
                                let ndx = Math.floor(Math.log(value.bytes) / Math.log(1000));
                                console.log("ndx????????????");
                                console.log(ndx);
                                $("#" + index + "_bytes").text(
                                    // Math.pow(base, exponent) ??????????????????????????????base???exponent??????
                                    // .toFixed()????????????????????????????????????????????????(????????????)???(2)????????????????????????
                                    (value.bytes / Math.pow(1000, ndx)).toFixed(2) + ' ' + fileSizeTypes[ndx]
                                );
                            } else { // ???bytes <= 0
                                $("#" + index + "_bytes").text("0");
                            }
                        });
                    }
                }
            });
      }
      $(this).blur(); // blur ??????????????????????????????????????????
  });

  // hook category functionality
  // ????????????????????????????????????Select category??????
  hook_firewall_categories();

  // expand internal auto generated rules
  // ??????????????????????????????
  // ???<tr>??????class internal-rule??????>0???
  if ($("tr.internal-rule").length > 0) {
      // ??????id expand-internal-rules??????
      $("#expand-internal-rules").show();
      // ??????id internal-rule-count????????????????????????"????????????" = ("tr.internal-rule").length)
      $("#internal-rule-count").text($("tr.internal-rule").length);
  }

  // our usual zebra striping doesn't respect hidden rows, hook repaint on .opnsense-rules change() and fire initially
  // ???????????????????????????
  $(".opnsense-rules > tbody > tr").each(function(){
      // save zebra color
      console.log("--------$(this)????????????---------");
      console.log($(this));
      console.log("--------$(this).children(0)????????????---------");
      console.log($(this).children(0));
      console.log("-------------------------------------------");
      // ????????????.opnsense-rules > tbody > tr????????????
      // .css() ???????????????
      let tr_color = $(this).children(0).css("background-color");
      console.log("--------tr_color????????????: tr??????????????????background-color??????---------");
      console.log(tr_color);
      console.log("-------------------------------------------");
      // ???????????????transparent ??? rgb(0, 0, 0')???
      if (tr_color != 'transparent' && !tr_color.includes('(0, 0, 0')) {
          // ??????????????????????????????
          console.log("--------$(#fw_category).data('stripe_color', tr_color);---------");
          console.log($("#fw_category").data('stripe_color', tr_color));
          $("#fw_category").data('stripe_color', tr_color); // data-stripe_color = tr_color
      }
  });
  // ???class ??? opnsense-rules ????????????"table-striped" class
  $(".opnsense-rules").removeClass("table-striped");

  $(".opnsense-rules").change(function(){
      // ??????.opnsense-rules > tbody > tr:visible(?????????tr) ???"background-color", "inherit"
      //  
      $(".opnsense-rules > tbody > tr:visible").each(function (index) {
          $(this).css("background-color", "inherit");
          // ( i % 2 == 0)??????????????????i?????????????????????
          // ???index??????2??? = 0???
          if ( index % 2 == 0) {
              // ?????????????????????background-color?????????"#fw_category"????????????
              $(this).css("background-color", $("#fw_category").data('stripe_color'));
          }
      });
  });
  // ???????????????????????????
  $("#expand-internal").click(function(event){
      event.preventDefault();
      $(".internal-rule").toggle(); // ??????/????????????
      $(".opnsense-rules").change(); // ??????
  });
});
</script>
<style>
    .view-stats {
        display: none;
    }
    .button-th {
        width: 150px;
    }
    .opnsense-rules > tbody > tr > td {
        padding-left:15px;
        padding-right:15px;
    }
</style>

<?php include("fbegin.inc"); ?>
  <div class="hidden">
    <!-- Inspect btn -->
    <div id="category_block" style="z-index:-100;">
        <select class="selectpicker hidden-xs hidden-sm hidden-md" data-live-search="true" data-size="5"  multiple title="<?=gettext("Select category");?>" id="fw_category">
        </select>
        <button id="btn_inspect" class="btn btn-default hidden-xs">
          <i class="fa fa-eye" aria-hidden="true"></i>
          <?=gettext("Inspect");?>
        </button>
    </div>
  </div>
  <section class="page-content-main">
    <div class="container-fluid">
      <div class="row">
        <!-- print_service_banner('firewall'); -->
        <!-- print_alert_box(sprintf(
              gettext(
                'The firewall has globally been disabled and configured rules are ' .
                'currently not enforced. It can be enabled in the %sFirewall/NAT%s ' .
                'settings.'
              ),
              '<a href="/system_advanced_firewall.php">',
              '</a>'
            )); -->
        <?php print_service_banner('firewall'); ?>
        <!-- Apply btn -->
        <div id="fw-alert-box" class="col-xs-12 <?=!is_subsystem_dirty('filter') && !isset($savemsg) ? "hidden":"";?>">
          <div class="alert alert-info" role="alert">
            <div id="fw-alert-changes" class="fw-alert-messages <?=!is_subsystem_dirty('filter') ? "hidden":"";?>">
                <label for="btn_apply">
                  <?=gettext("The firewall rule configuration has been changed.<br />You must apply the changes in order for them to take effect.");?>
                </label>
                <button id="btn_apply" class="btn btn-primary pull-right" value="Apply changes"><?=gettext("Apply changes");?></button>
            </div>
            <div id="fw-alert-message" class="fw-alert-messages <?=!isset($savemsg) ? "hidden":"";?>">
                <?=isset($savemsg) ? $savemsg : "";?>
            </div>
          </div>
        </div>
<?php
          $interface_has_rules = false;
          foreach ($a_filter as $i => $filterent) {
            if ((!isset($filterent['floating']) && $selected_if == $filterent['interface']) ||
              ((isset($filterent['floating']) || empty($filterent['interface'])) && $selected_if == 'FloatingRules')) {
              $interface_has_rules = true;
              break;
            }
          } ?>
<?php if (!$interface_has_rules): ?>
  <?php if ($selected_if == 'FloatingRules'): ?>
          <?php print_info_box(gettext('No floating rules are currently defined. Floating rules are ' .
            'not bound to a single interface and can therefore be used to span ' .
            'policies over multiple networks at the same time.')) ?>
  <?php else: ?>
          <?php print_info_box(sprintf(gettext('No %s rules are currently defined. All incoming connections ' .
            'on this interface will be blocked until you add a pass rule. Exceptions for automatically generated ' .
            'rules may apply.'),
            !empty($config['interfaces'][$selected_if]['descr']) ? // ???interfaces??????????????????
            // %s = $config['interfaces'][$selected_if]['descr'] ?????????????????????????????????$selected_if(??????)
            $config['interfaces'][$selected_if]['descr'] : strtoupper($selected_if))) ?>
  <?php endif ?>
<?php endif ?>
        <section class="col-xs-12">
          <div class="content-box">
            <form action="firewall_rules.php?if=<?=$selected_if;?>" method="post" name="iform" id="iform">
              <input id="id" name="id" value="" />
              <input id="action" name="act" value="" />
              <!-- <input type="hidden" id="id" name="id" value="" />
              <input type="hidden" id="action" name="act" value="" /> -->
              <div class="table-responsive">
                <table class="table table-condensed table-striped opnsense-rules">
                  <tbody>
                    <tr>
                      <td><input type="checkbox" id="selectAll"></td>
                      <td>&nbsp;</td>
                      <td class="view-info"><strong><?= gettext('Protocol') ?></strong></td>
                      <td class="view-info"><strong><?= gettext('Source') ?></strong></td>
                      <td class="view-info hidden-xs hidden-sm"><strong><?= gettext('Port') ?></strong></td>
                      <td class="view-info hidden-xs hidden-sm"><strong><?= gettext('Destination') ?></strong></td>
                      <td class="view-info hidden-xs hidden-sm"><strong><?= gettext('Port') ?></strong></td>
                      <td class="view-info hidden-xs hidden-sm"><strong><?= gettext('Gateway') ?></strong></td>
                      <td class="view-info hidden-xs hidden-sm"><strong><?= gettext('Schedule') ?></strong></td>
                      <td class="view-stats hidden-xs hidden-sm"><strong><?= gettext('Evaluations') ?></strong></td>
                      <td class="view-stats hidden-xs hidden-sm"><strong><?= gettext('States') ?></strong></td>
                      <td class="view-stats"><strong><?= gettext('Packets') ?></strong></td>
                      <td class="view-stats"><strong><?= gettext('Bytes') ?></strong></td>
                      <td class="view-info"><strong><?= gettext('Interfaces') ?></strong></td>
                      <td class="text-nowrap">
                        <strong><?= gettext('Description') ?></strong>
                        <i class="fa fa-question-circle" data-toggle="collapse" data-target=".rule_md5_hash" ></i>
                      </td>
                      <!-- ???????????? -->
                      <td class="text-nowrap button-th">
                        <!-- add???????????????$selected_if???????????????add?????? -->
                        <a href="<?= url_safe('firewall_rules_edit.php?if=%s', array($selected_if)) ?>" class="btn btn-primary btn-xs" data-toggle="tooltip" title="<?= html_safe(gettext('Add')) ?>">
                          <i class="fa fa-plus fa-fw"></i>
                        </a>
                        <!-- ??????????????????????????? -->
                        <button id="move_<?= count($a_filter) ?>" name="move_<?= count($a_filter) ?>_x" data-toggle="tooltip" title="<?= html_safe(gettext('Move selected rules to end')) ?>" class="act_move btn btn-default btn-xs">
                          <i class="fa fa-arrow-left fa-fw"></i>
                        </button>
                        <button id="del_x" title="<?= html_safe(gettext('Delete selected')) ?>" data-toggle="tooltip" class="act_delete btn btn-default btn-xs">
                          <i class="fa fa-trash fa-fw"></i>
                        </button>
                        <button title="<?= html_safe(gettext('Enable selected')) ?>" data-toggle="tooltip" class="act_toggle_enable btn btn-default btn-xs">
                          <i class="fa fa-check-square-o fa-fw"></i>
                        </button>
                        <button title="<?= html_safe(gettext('Disable selected')) ?>" data-toggle="tooltip" class="act_toggle_disable btn btn-default btn-xs">
                          <i class="fa fa-square-o fa-fw"></i>
                        </button>
                      </td>
                  </tr>
                  <!-- expand-internal-rules -->
                  <tr id="expand-internal-rules" style="display: none;">
                      <td><i class="fa fa-folder-o text-muted"></i></td>
                      <td></td>
                      <td class="view-info" colspan="2"> </td>
                      <td class="view-info hidden-xs hidden-sm" colspan="5"> </td>
                      <td colspan="2" class="view-stats hidden-xs hidden-sm"></td>
                      <td colspan="2" class="view-stats"></td>
                      <td><?= gettext('Automatically generated rules') ?></td>
                      <td>
                          <button class="btn btn-default btn-xs" id="expand-internal">
                            <i class="fa fa-chevron-circle-down" aria-hidden="true"></i>
                            <span class="badge">
                              <span id="internal-rule-count"><span>
                            </span>
                          </button>
                      </td>
                  </tr>
<?php
                $fw = filter_core_get_initialized_plugin_system();
                filter_core_bootstrap($fw);
                plugins_firewall($fw); // ????????????
                foreach ($fw->iterateFilterRules() as $rule):
                    $is_selected = $rule->getInterface() == $selected_if || (
                        ($rule->getInterface() == "" || strpos($rule->getInterface(), ",") !== false) && $selected_if == "FloatingRules"
                    );
                    if ($rule->isEnabled() && $is_selected):
                        $filterent = $rule->getRawRule();
                        $filterent['quick'] = !isset($filterent['quick']) || $filterent['quick'];
                        legacy_html_escape_form_data($filterent);?>
                    <tr class="internal-rule" style="display: none;">
                      <td><i class="fa fa-magic"></i></td>
                      <td>
                          <span class="<?=firewall_rule_item_action($filterent);?>"></span>
                          <?=firewall_rule_item_icons($filterent);?>
                          <i class="<?=firewall_rule_item_log($filterent);?>"></i>
                      </td>
                      <td class="view-info">
                          <?=firewall_rule_item_proto($filterent);?>
                      </td>
                      <td class="view-info">
                          <?=!empty($filterent['from']) ? $filterent['from'] : "*";?>
                      </td>
                      <td class="view-info hidden-xs hidden-sm">
                          <?=!empty($filterent['from_port']) ? $filterent['from_port'] : "*";?>
                      </td>
                      <td class="view-info hidden-xs hidden-sm">
                          <?=!empty($filterent['to']) ? $filterent['to'] : "*";?>
                      </td>
                      <td class="view-info hidden-xs hidden-sm">
                          <?=!empty($filterent['to_port']) ? $filterent['to_port'] : "*";?>
                      </td>
                      <td class="view-info hidden-xs hidden-sm">
                        <?= !empty($filterent['gateway']) ? $filterent['gateway'] : "*";?>
                      </td>
                      <td class="view-info hidden-xs hidden-sm">*</td>
                      <td class="view-stats hidden-xs hidden-sm" id="<?=$rule->getLabel();?>_evaluations"><?= gettext('N/A') ?></td>
                      <td class="view-stats hidden-xs hidden-sm">
                          <a href="/ui/diagnostics/firewall/states#<?=html_safe($rule->getLabel());?>" id="<?=$rule->getLabel();?>_states" data-toggle="tooltip" title="<?=html_safe("open states view");?>" ><?=  gettext('N/A');?></a>
                      <td class="view-stats" id="<?=$rule->getLabel();?>_packets"><?= gettext('N/A') ?></td>
                      <td class="view-stats" id="<?=$rule->getLabel();?>_bytes"><?= gettext('N/A') ?></td>
                      <td class="view-info">
                        <?= !empty($filterent['interface']) ? $filterent['interface'] : "*";?>
                      </td>
                      <td><?=$rule->getDescr();?></td>
                      <td>
<?php if (!empty($rule->getRef())): ?>
                          <a href="firewall_rule_lookup.php?rid=<?=html_safe($rule->getLabel());?>" class="btn btn-default btn-xs"><i class="fa fa-fw fa-search"></i></a>
<?php endif ?>
                      </td>
                    </tr>
<?php
                    endif;
                endforeach;?>
<?php
                foreach ($a_filter as $i => $filterent):
                if (
                    (!isset($filterent['floating']) && $selected_if == $filterent['interface']) ||
                     (
                        (isset($filterent['floating']) || empty($filterent['interface'])) &&
                        $selected_if == 'FloatingRules'
                     )
                ):
                  // calculate a hash so we can track these records in the ruleset, new style (mvc) code will
                  // automatically provide us with a uuid, this is a workaround to provide some help with tracking issues.
                  $rule_hash = OPNsense\Firewall\Util::calcRuleHash($a_filter_raw[$i]);
?>
                  <tr class="rule  <?=isset($filterent['disabled'])?"text-muted":"";?>" data-category="<?=!empty($filterent['category']) ? $filterent['category'] : "";?>">
                    <td>
                      <input class="rule_select" type="checkbox" name="rule[]" value="<?=$i;?>"  />
                    </td>
                    <td>
                      <i class="act_toggle <?=firewall_rule_item_action($filterent);?>" style="cursor: pointer;" id="toggle_<?=$i;?>" data-toggle="tooltip" title="<?= html_safe(empty($filterent['disabled']) ? gettext('Disable rule') : gettext('Enable rule')) ?>"></i>
                      <?=firewall_rule_item_icons($filterent);?>
                      <i class="act_log <?= firewall_rule_item_log($filterent) ?>" style="cursor: pointer;" id="toggle_<?=$i;?>" data-toggle="tooltip" title="<?= html_safe(empty($filterent['log']) ? gettext('Enable logging') : gettext('Disable logging')) ?>"></i>
                    </td>
                    <td class="view-info">
                        <?=firewall_rule_item_proto($filterent);?>
                    </td>
                    <td class="view-info">
<?php                 if (isset($filterent['source']['address']) && is_alias($filterent['source']['address'])): ?>
                        <span title="<?=htmlspecialchars(get_alias_description($filterent['source']['address']));?>" data-toggle="tooltip"  data-html="true">
                          <?=htmlspecialchars(pprint_address($filterent['source']));?>&nbsp;
                        </span>
                        <a href="/ui/firewall/alias/index/<?=htmlspecialchars($filterent['source']['address']);?>"
                            title="<?=gettext("edit alias");?>" data-toggle="tooltip">
                          <i class="fa fa-list"></i>
                        </a>
<?php                 else: ?>
                        <?=htmlspecialchars(pprint_address($filterent['source']));?>
<?php                 endif; ?>
                    </td>

                    <td class="view-info hidden-xs hidden-sm">
<?php                 if (isset($filterent['source']['port']) && is_alias($filterent['source']['port'])): ?>
                        <span title="<?=htmlspecialchars(get_alias_description($filterent['source']['port']));?>" data-toggle="tooltip"  data-html="true">
                          <?=htmlspecialchars(pprint_port($filterent['source']['port'])); ?>&nbsp;
                        </span>
                        <a href="/ui/firewall/alias/index/<?=htmlspecialchars($filterent['source']['port']);?>"
                            title="<?=gettext("edit alias");?>" data-toggle="tooltip">
                          <i class="fa fa-list"></i>
                        </a>
<?php                 else: ?>
                        <?=htmlspecialchars(pprint_port(isset($filterent['source']['port']) ? $filterent['source']['port'] : null)); ?>
<?php                 endif; ?>
                    </td>

                    <td class="view-info hidden-xs hidden-sm">
<?php                 if (isset($filterent['destination']['address']) && is_alias($filterent['destination']['address'])): ?>
                        <span title="<?=htmlspecialchars(get_alias_description($filterent['destination']['address']));?>" data-toggle="tooltip"  data-html="true">
                          <?=htmlspecialchars(pprint_address($filterent['destination'])); ?>
                        </span>
                        <a href="/ui/firewall/alias/index/<?=htmlspecialchars($filterent['destination']['address']);?>"
                            title="<?=gettext("edit alias");?>" data-toggle="tooltip">
                          <i class="fa fa-list"></i>
                        </a>
<?php                 else: ?>
                        <?=htmlspecialchars(pprint_address($filterent['destination'])); ?>
<?php                 endif; ?>
                    </td>

                    <td class="view-info hidden-xs hidden-sm">
<?php                 if (isset($filterent['destination']['port']) && is_alias($filterent['destination']['port'])): ?>
                        <span title="<?=htmlspecialchars(get_alias_description($filterent['destination']['port']));?>" data-toggle="tooltip"  data-html="true">
                          <?=htmlspecialchars(pprint_port($filterent['destination']['port'])); ?>&nbsp;
                        </span>
                        <a href="/ui/firewall/alias/index/<?=htmlspecialchars($filterent['destination']['port']);?>"
                            title="<?=gettext("edit alias");?>" data-toggle="tooltip">
                          <i class="fa fa-list"></i>
                        </a>
<?php                 else: ?>
                        <?=htmlspecialchars(pprint_port(isset($filterent['destination']['port']) ? $filterent['destination']['port'] : null)); ?>
<?php                 endif; ?>
                    </td>

                    <td class="view-info hidden-xs hidden-sm">
<?php
                       if (isset($filterent['gateway'])):?>
                      <?=isset($config['interfaces'][$filterent['gateway']]['descr']) ? htmlspecialchars($config['interfaces'][$filterent['gateway']]['descr']) : htmlspecialchars(pprint_port($filterent['gateway'])); ?>
<?php
                      else: ?>
                      *
<?php                 endif; ?>
                    </td>
                    <td class="view-info hidden-xs hidden-sm">
<?php
                      if (!empty($filterent['sched'])):?>
<?php
                        $schedule_descr = "";
                        if (isset($config['schedules']['schedule']))
                        {
                            foreach ($config['schedules']['schedule'] as $schedule)
                            {
                                if ($schedule['name'] == $filterent['sched'])
                                {
                                    $schedule_descr = (isset($schedule['descr'])) ? $schedule['descr'] : "";
                                    break;
                                }
                            }
                        }
?>
                        <span title="<?=htmlspecialchars($schedule_descr);?>" data-toggle="tooltip">
                          <?=htmlspecialchars($filterent['sched']);?>&nbsp;
                        </span>
                        <a href="/firewall_schedule_edit.php?name=<?=htmlspecialchars($filterent['sched']);?>"
                            title="<?= html_safe(gettext('Edit')) ?>" data-toggle="tooltip">
<?php
                        if (filter_get_time_based_rule_status($schedule)):?>
                          <i class="fa fa-calendar text-success"></i>
<?php
                        else:?>
                          <i class="fa fa-calendar text-muted"></i>
<?php
                        endif;?>
                        </a>
<?php
                      else: ?>
                      *
<?php
                       endif;?>
                    </td>
                    <td class="view-stats hidden-xs hidden-sm" id="<?=$rule_hash;?>_evaluations"><?= gettext('N/A') ?></td>
                    <td class="view-stats hidden-xs hidden-sm">
                      <a href="/ui/diagnostics/firewall/states#<?=html_safe($rule_hash);?>" id="<?=$rule_hash;?>_states" data-toggle="tooltip" title="<?=html_safe("open states view");?>" ><?= gettext('N/A') ?></a>
                    </td>
                    <td class="view-stats" id="<?=$rule_hash;?>_packets"><?= gettext('N/A') ?></td>
                    <td class="view-stats" id="<?=$rule_hash;?>_bytes"><?= gettext('N/A') ?></td>
                    <td class="view-info">
                        <?= !empty($filterent['interface']) ? $filterent['interface'] : "*";?>
                    </td>
                    <td  class="rule-description">
                      <?=$filterent['descr'];?>
                      <div class="collapse rule_md5_hash">
                          <small><?=$rule_hash;?></small>
                      </div>
                    </td>
                    <td>
                      <button id="move_<?=$i;?>" name="move_<?=$i;?>_x" data-toggle="tooltip" title="<?= html_safe(gettext("Move selected rules before this rule")) ?>" class="act_move btn btn-default btn-xs">
                        <i class="fa fa-arrow-left fa-fw"></i>
                      </button>
<?php if (isset($filterent['type'])): ?>
<?php
                      // not very nice.... associated NAT rules don't have a type...
                      // if for some reason (broken config) a rule is in there which doesn't have a related nat rule
                      // make sure we are able to delete it.
?>
                      <a href="firewall_rules_edit.php?if=<?=$selected_if;?>&id=<?=$i;?>" data-toggle="tooltip" title="<?= html_safe(gettext('Edit')) ?>" class="btn btn-default btn-xs">
                        <i class="fa fa-pencil fa-fw"></i>
                      </a>
                      <a href="firewall_rules_edit.php?if=<?=$selected_if;?>&dup=<?=$i;?>" class="btn btn-default btn-xs" data-toggle="tooltip" title="<?= html_safe(gettext('Clone')) ?>">
                        <i class="fa fa-clone fa-fw"></i>
                      </a>
<?php endif ?>
                      <a id="del_<?=$i;?>" title="<?= html_safe(gettext('Delete')) ?>" data-toggle="tooltip"  class="act_delete btn btn-default btn-xs">
                        <i class="fa fa-trash fa-fw"></i>
                      </a>
                    </td>
                  </tr>
<?php
                  endif;
                  endforeach;
                  $i++;
?>
                </tbody>
              </table>
              <!-- ?????????????????? -->
              <table class="table table-condensed table-striped opnsense-rules">
                <tbody>
                  <tr class="hidden-xs hidden-sm">
                    <td>
                      <table style="width:100%; border:0;">
                        <tr>
                          <td style="width:16px"><span class="fa fa-play text-success"></span></td>
                          <td style="width:100px"><?=gettext("pass");?></td>
                          <td style="width:14px"></td>
                          <td style="width:16px"><span class="fa fa-times text-danger"></span></td>
                          <td style="width:100px"><?=gettext("block");?></td>
                          <td style="width:14px"></td>
                          <td style="width:16px"><span class="fa fa-times-circle text-danger"></span></td>
                          <td style="width:100px"><?=gettext("reject");?></td>
                          <td style="width:14px"></td>
                          <td style="width:16px"><span class="fa fa-info-circle text-info"></span></td>
                          <td style="width:100px"><?=gettext("log");?></td>
                          <td style="width:16px"><span class="fa fa-long-arrow-right text-info"></span></td>
                          <td style="width:100px"><?=gettext("in");?></td>
                          <td style="width:16px"><span class="fa fa-flash text-warning"></span></td>
                          <td style="width:100px"><?=gettext("first match");?></td>
                        </tr>
                        <tr>
                          <td><span class="fa fa-play text-muted"></span></td>
                          <td class="nowrap"><?=gettext("pass (disabled)");?></td>
                          <td>&nbsp;</td>
                          <td><span class="fa fa-times text-muted"></span></td>
                          <td class="nowrap"><?=gettext("block (disabled)");?></td>
                          <td>&nbsp;</td>
                          <td><span class="fa fa-times-circle text-muted"></span></td>
                          <td class="nowrap"><?=gettext("reject (disabled)");?></td>
                          <td>&nbsp;</td>
                          <td style="width:16px"><span class="fa fa-info-circle text-muted"></span></td>
                          <td class="nowrap"><?=gettext("log (disabled)");?></td>
                          <td style="width:16px"><span class="fa fa-long-arrow-left"></span></td>
                          <td style="width:100px"><?=gettext("out");?></td>
                          <td style="width:16px"><span class="fa fa-flash text-muted"></span></td>
                          <td style="width:100px"><?=gettext("last match");?></td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr class="hidden-xs hidden-sm">
                    <td>
                      <i class="fa fa-calendar fa-fw text-success"></i>
                      <i class="fa fa-calendar fa-fw text-muted"></i>
                      <?= gettext('Active/Inactive Schedule (click to view/edit)') ?></td>
                    </td>
                  </tr>
                  <tr class="hidden-xs hidden-sm">
                    <td>
                      <i class="fa fa-list fa-fw text-primary"></i>
                      <?= gettext('Alias (click to view/edit)') ?>
                    </td>
                  </tr>
                  <tr class="hidden-xs hidden-sm">
                    <td>
<?php if ('FloatingRules' != $selected_if): ?>
                      <?= sprintf(gettext('%s rules are evaluated on a first-match basis by default (i.e. ' .
                        'the action of the first rule to match a packet will be executed). ' .
                        'This means that if you use block rules, you will have to pay attention ' .
                        'to the rule order. Everything that is not explicitly passed is blocked ' .
                        'by default.'), !empty($config['interfaces'][$selected_if]['descr']) ?
                        $config['interfaces'][$selected_if]['descr'] : strtoupper($selected_if)) ?>
<?php else: ?>
                        <?= gettext('Floating rules are evaluated on a first-match basis (i.e. ' .
                        'the action of the first rule to match a packet will be executed) only ' .
                        'if the "quick" option is checked on a rule. Otherwise they will only apply if no ' .
                        'other rules match. Pay close attention to the rule order and options ' .
                        'chosen. If no rule here matches, the per-interface or default rules are used.') ?>
<?php endif ?>
<?php
          echo('<br/>$a_nat????????????<br/>');
          $a_nat = &config_read_array('nat', 'rule');
          print_r ($a_nat);
          echo('<br/>$config['.'interfaces'.']????????????<br/>');
          print_r ($config['interfaces']);
          
          $path = '/usr/local/etc/inc/plugins.inc.d/';
          $clash = '/usr/local/etc/inc/';
          $ext = '.inc';
          echo('<br/>$plugins????????????<br/>');
          $plugins = glob($path . '*' . $ext);
          sort($plugins); // ??????KEY????????????????????????(A~z)???????????????
          print_r ($plugins);
          
          
          echo('<br/>plugins???function?????????:<br/>');
          if (function_exists('ipsec_interfaces')) {
            echo ('ipsec???ipsec_interfaces<br/>');
          }else{
            echo('???');
          };
          
          if (function_exists('loopback_interfaces')) {
            echo ('loopback???loopback_interfaces<br/>');
          }else{
            echo('???');
          };

          if (function_exists('openvpn_interfaces')) {
            echo ('openvpn???openvpn_interfaces<br/>');
          }else{
            echo('???');
          };
          
          if (function_exists('pf_interfaces')) {
            echo ('pf???pf_interfaces<br/>');
          }else{
            echo('???');
          };

          echo('<br/>$intf_config = &config_read_array('.'interfaces'.', '.'lo0'.');????????????:<br/>');
          $intf_conf = &config_read_array('interfaces', 'lo0');
          print_r ($intf_conf);
          
          echo('<br/>$pconfig????????????:<br/>');
          $pconfig = $_POST;
          print_r ($pconfig);
          
          echo('<br/>$_GET????????????:<br/>');
          $_GET_if = $_GET;
          print_r ($_GET_if);
          
          echo('<br/>$a_filter????????????:<br/>');
          print_r ($a_filter);

          echo('<br/>$a_filter_raw????????????:<br/>');
          print_r ($a_filter_raw);

          echo('<br/>$a_filter_org????????????:<br/>');
          $a_filter_org = &config_read_array('filter', 'rule');
          print_r ($a_filter_org);
          
          echo('<br/>$stream????????????:<br/>');
          $configdSocket = '/var/run/configd.socket';
          $errorMessage = "";
          $poll_timeout = 2;
          $stream = @stream_socket_client('unix:///var/run/configd.socket', $errorNumber, $errorMessage, $poll_timeout);
          print_r ($stream);

          echo('<br/>fwrite($stream, \'filter rule stats\');??????????????????:<br/>');
          $stream_fwrite = fwrite($stream, 'filter rule stats');
          print_r ($stream_fwrite);

          echo('<br/>str_replace($endOfStream, \'\', $resp);????????????:<br/>');
          $errorOfStream = 'Execute error';
          $resp = '';
          while (true) {
              $resp = $resp . stream_get_contents($stream);

              if (strpos($resp, $endOfStream) !== false) {
                  // end of stream detected, exit
                  break;
              }
          }
          $return = str_replace($endOfStream, '', $resp);
          print_r ($return);

          echo('<br/>json_decode($return, true);????????????:<br/>');
          $result = json_decode($return, true);
          print_r ($result);
          
          echo('$fw ????????????:<br/>');
          print_r ($fw);
          
          echo('$filterent ????????????:<br/>');
          print_r ($filterent);

          echo('$rule ????????????:<br/>');
          print_r ($rule);

          ?>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </form>
        </div>
      </section>
    </div>
  </div>

</section>
<?php include("foot.inc"); ?>

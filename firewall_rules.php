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
            // is_ipaddr() 從util.inc調用
            // strpos($filterent['from'], ":")為找出 ":"第一次出現的位置 ， false=沒有在($filterent['from']中
            // 如果沒有":"     $record_ipprotocol = "IPv4 "
            // 有":"    $record_ipprotocol = "IPv6 "
            $record_ipprotocol = strpos($filterent['from'], ":") === false ? "IPv4 " :  "IPv6 ";
          // 取$filterent['to'] 確認 $record_ipprotocol 
        } elseif (!empty($filterent['to']) && is_ipaddr(explode("/", $filterent['to'])[0])) {
            $record_ipprotocol = strpos($filterent['to'], ":") === false ? "IPv4 " :  "IPv6 ";
          // 取$filterent['source']['address'] 確認 $record_ipprotocol 
        } elseif (isset($filterent['source']['address'])
                    && is_ipaddr(explode("/", $filterent['source']['address'])[0])) {
            $record_ipprotocol = strpos($filterent['source']['address'], ":") === false ? "IPv4 " : "IPv6 ";
          // 取$filterent['destination']['address'] 確認 $record_ipprotocol 
        } elseif (isset($filterent['destination']['address'])
                    && is_ipaddr(explode("/", $filterent['destination']['address'])[0])) {
            $record_ipprotocol = strpos($filterent['destination']['address'], ":") === false ? "IPv4 " : "IPv6 ";
        } else {
            $record_ipprotocol = "IPv4+6 ";
        }
    }
    // ICMP 協定(ICMP 協定說明 : http://www.tsnien.idv.tw/Internet_WebBook/chap5/5-4%20ICMP%20%E9%80%9A%E8%A8%8A%E5%8D%94%E5%AE%9A.html)
    // Internet中一種稱為『網際控制訊息協定』（Internet Control Message Protocol, ICMP）的通訊軟體，用來偵測網路的狀況。
    // Ping是透過ICMP的Echo Request和Echo Reply來完成檢測。

    // ICMP 訊息型態:
    $icmptypes = array(
      "" => gettext("any"),
      "echoreq" => gettext("Echo Request"), // 回應要求
      "echorep" => gettext("Echo Reply"),   // 回應答覆
      "unreach" => gettext("Destination Unreachable"), // 目的地無法到達
      "squench" => gettext("Source Quench (Deprecated)"), // 來源抑制(已棄用)
      "redir" => gettext("Redirect"), // 改變傳輸路徑
      "althost" => gettext("Alternate Host Address (Deprecated)"), // 備用主機地址(已棄用)
      "routeradv" => gettext("Router Advertisement"), // 路由器宣傳
      "routersol" => gettext("Router Solicitation"), // 路由器請求
      "timex" => gettext("Time Exceeded"), // 溢時傳輸
      "paramprob" => gettext("Parameter Problem"), // 參數問題
      "timereq" => gettext("Timestamp"), // 時間標籤要求
      "timerep" => gettext("Timestamp Reply"), // 時間標籤回覆
      "inforeq" => gettext("Information Request (Deprecated)"), // 資訊要求(已棄用)
      "inforep" => gettext("Information Reply (Deprecated)"), // 資訊回覆(已棄用)
      "maskreq" => gettext("Address Mask Request (Deprecated)"), // 位址遮罩要求(已棄用)
      "maskrep" => gettext("Address Mask Reply (Deprecated)")// 位址遮罩回覆(已棄用)
    );
    // ICMPv6 訊息型態:
    $icmp6types = array(
      "" => gettext("any"),
      "unreach" => gettext("Destination unreachable"), // 目的地無法到達
      "toobig" => gettext("Packet too big"), // 數據包太大
      "timex" => gettext("Time exceeded"), // 溢時傳輸
      "paramprob" => gettext("Invalid IPv6 header"), // 無效的 IPv6 標頭
      "echoreq" => gettext("Echo service request"), // 服務請求
      "echorep" => gettext("Echo service reply"), // 服務回覆
      "groupqry" => gettext("Group membership query"), // 群組成員查詢
      "listqry" => gettext("Multicast listener query"), // 聆聽者查詢
      "grouprep" => gettext("Group membership report"),// 群組成員查詢回覆
      "listenrep" => gettext("Multicast listener report"), // 聆聽者查詢
      "groupterm" => gettext("Group membership termination"), // 群組成員資格終止
      "listendone" => gettext("Multicast listener done"), // 聆聽者查詢終止
      "routersol" => gettext("Router solicitation"), // 路由器請求
      "routeradv" => gettext("Router advertisement"), // 路由器宣傳
      "neighbrsol" => gettext("Neighbor solicitation"), // 鄰居請求
      "neighbradv" => gettext("Neighbor advertisement"), // 鄰居宣傳
      "redir" => gettext("Shorter route exists"), // 存在較短的路線
      "routrrenum" => gettext("Route renumbering"), // 路線重新編號
      "fqdnreq" => gettext("FQDN query"), // 完整網域名稱 FQDN（Fully Qualified Domain Name）請求
      "niqry" => gettext("Node information query"), // 節點信息查詢
      "wrureq" => gettext("Who-are-you request"), // 你是誰請求
      "fqdnrep" => gettext("FQDN reply"), // 網域名稱 FQDN（Fully Qualified Domain Name）回覆
      "nirep" => gettext("Node information reply"), // 節點信息回覆
      "wrurep" => gettext("Who-are-you reply"), // 你是誰回覆
      "mtraceresp" => gettext("mtrace response"), // 跟踪響應
      "mtrace" => gettext("mtrace messages") // 跟踪消息
    );
    // 當$filterent['protocol']有內容&& == "icmp" && !empty($filterent['icmptype'])
    if (isset($filterent['protocol']) && $filterent['protocol'] == "icmp" && !empty($filterent['icmptype'])) {
        $result = $record_ipprotocol;
        // html_safe()調用於guiconfig.inc
        // strtoupper()把字符串轉換為大寫
        $result .= sprintf(
          "<span data-toggle=\"tooltip\" title=\"ICMP type: %s \"> %s </span>",
          html_safe($icmptypes[$filterent['icmptype']]),
          isset($filterent['protocol']) ? strtoupper($filterent['protocol']) : "*"
        );
        return $result;
    // 當$filterent['protocol']有內容 && !empty($filterent['icmp6-type'])
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
    // 若$filterent['direction']為空值 or $filterent['direction'] == "in"
    if (empty($filterent['direction']) || $filterent['direction'] == "in") {
        // $result = <i class="fa fa-long-arrow-right fa-fw text-info" data-toggle="tooltip" title="in"></i>
        $result .= sprintf(
            "<i class=\"fa fa-long-arrow-right fa-fw text-info\" data-toggle=\"tooltip\" title=\"%s\"></i>",
            gettext("in")
        );
    // 若$filterent['direction']非為空值 and $filterent['direction'] == "out"
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
    // 若$filterent['floating']為空值 and $filterent['quick'] === null
    if (empty($filterent['floating']) && $filterent['quick'] === null){
        $is_quick = true;
    // 若$filterent['floating']為非空值 and $filterent['quick'] === null
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
    // 若$filterent['type'] == "block" and $filterent['disabled']為空值
    if ($filterent['type'] == "block" && empty($filterent['disabled'])) {
        return "fa fa-times fa-fw text-danger";
    // 若$filterent['type'] == "block" and $filterent['disabled']非為空值
    } elseif ($filterent['type'] == "block" && !empty($filterent['disabled'])) {
        return "fa fa-times fa-fw text-muted";
    // 若$filterent['type'] == "reject" and $filterent['disabled']為空值
    }  elseif ($filterent['type'] == "reject" && empty($filterent['disabled'])) {
        return "fa fa-times-circle fa-fw text-danger";
    // 若$filterent['type'] == "reject" and $filterent['disabled']為空值
    }  elseif ($filterent['type'] == "reject" && !empty($filterent['disabled'])) {
        return "fa fa-times-circle fa-fw text-muted";
    // 若$filterent['disabled']為空值
    } elseif (empty($filterent['disabled'])) {
        return "fa fa-play fa-fw text-success";
    } else {
        return "fa fa-play fa-fw text-muted";
    }
}

function firewall_rule_item_log($filterent)
{
    // 當$filterent['log'] == true
    if ($filterent['log'] == true) {
        return "fa fa-info-circle fa-fw text-info";
    } else {
        return "fa fa-info-circle fa-fw text-muted";
    }
}
/***********************************************************************************************************
 *
 ***********************************************************************************************************/

$a_filter = &config_read_array('filter', 'rule'); // 回傳取得的config_array資料

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_GET['if'])) {
        $current_if = htmlspecialchars($_GET['if']); // 取得要前往的頁面名稱
    } else {
        $current_if = "FloatingRules"; // 預設頁面
    }
    // 取得POST傳遞的資料
    // 透過iform傳送POST資料
    // <form action="firewall_rules.php?if=<?=$selected_if>;" method="post" name="iform" id="iform">
    // <input type="hidden" id="id" name="id" value="" />
    // <input type="hidden" id="action" name="act" value="" />
    $pconfig = $_POST;
    // 當$pconfig['id']存在並$a_filter[$pconfig['id']])也存在時
    if (isset($pconfig['id']) && isset($a_filter[$pconfig['id']])) {
        // id found and valid
        $id = $pconfig['id'];
    }
    // 當$pconfig['act']存在並== "apply"時
    if (isset($pconfig['act']) && $pconfig['act'] == "apply") {
        system_cron_configure(); // 從system.inc調用
        filter_configure(); // 從filter.inc調用
        clear_subsystem_dirty('filter'); // 從util.inc調用
        $savemsg = get_std_save_message(); // 從guiconfig.inc調用
    // 當$pconfig['act']存在 並 == "del" 並且有$id時
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'del' && isset($id)) {
        // delete single item
        // 當$a_filter[$id]['associated-rule-id'])非空值時
        if (!empty($a_filter[$id]['associated-rule-id'])) {
            // unlink nat entry
            // 當$config['nat']['rule']存在時
            if (isset($config['nat']['rule'])) {
                // 取得config_array資料
                $a_nat = &config_read_array('nat', 'rule');
                foreach ($a_nat as &$natent) {
                    if ($natent['associated-rule-id'] == $a_filter[$id]['associated-rule-id']) {
                        $natent['associated-rule-id'] = ''; // 刪除此規則
                    }
                }
            }
        }
        unset($a_filter[$id]); // 清除變數內容
        write_config(); // 從config.inc調用，用於修改config
        mark_subsystem_dirty('filter');
        // 從util.inc調用，用於設置文件的訪問和修改時間
        // function mark_subsystem_dirty($subsystem = '')
        // {
        //     // touch(filename, time, atime)  設置指定文件的訪問和修改時間
        //     // filename 必須 要設置的文件 > "/tmp/{$subsystem}.dirty"
        //     // time 可選 設置時間(預設為系統時間)
        //     // atime 可選 設置訪問時間(預設為系統時間)
        //     touch("/tmp/{$subsystem}.dirty");
        // }
        
        //  $current_if = htmlspecialchars($_GET['if']);
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
      // 當$pconfig['act']存在 and == "del_x" and 有$pconfig['rule'] and $pconfig['rule']內容筆數>0
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'del_x' && isset($pconfig['rule']) && count($pconfig['rule']) > 0) {
        // delete selected rules 用於刪除選取的rules
        foreach ($pconfig['rule'] as $rulei) {
            // unlink nat entry
            if (isset($config['nat']['rule'])) {
                $a_nat = &config_read_array('nat', 'rule');
                foreach ($a_nat as &$natent) {
                    if ($natent['associated-rule-id'] == $a_filter[$rulei]['associated-rule-id']) {
                        $natent['associated-rule-id'] = ''; // 解除rule的鏈接
                    }
                }
            }
            unset($a_filter[$rulei]); // 清除被刪除的rule
        }
        write_config();
        mark_subsystem_dirty('filter');
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
        // 當$pconfig['act']有設置 and $pconfig['act']中有'toggle_enable', 'toggle_disable' and $pconfig['rule'])有設置 and $pconfig['rule']內容筆數大於0
    } elseif (isset($pconfig['act']) && in_array($pconfig['act'], array('toggle_enable', 'toggle_disable')) && isset($pconfig['rule']) && count($pconfig['rule']) > 0) {
        foreach ($pconfig['rule'] as $rulei) { // 取出$pconfig['rule']
            // 將$a_filter[$rulei]['disabled']設為toggle_disable
            $a_filter[$rulei]['disabled'] = $pconfig['act'] == 'toggle_disable';
        }
        write_config();
        mark_subsystem_dirty('filter');
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
        // 當$pconfig['act']存在 並== 'move'時 and 有設置$pconfig['rule']內容筆數大於0
    } elseif ( isset($pconfig['act']) && $pconfig['act'] == 'move' && isset($pconfig['rule']) && count($pconfig['rule']) > 0) {
        // move selected rules
        if (!isset($id)) { // 當沒有設置id時
            // if rule not set/found, move to end
            $id = count($a_filter); // id = 最大數筆數(排到最後)
        }
        // 移動rule排序，從legacy_bindings.inc調用legacy_move_config_list_items()
        $a_filter = legacy_move_config_list_items($a_filter, $id,  $pconfig['rule']);
        write_config();
        mark_subsystem_dirty('filter');
        header(url_safe('Location: /firewall_rules.php?if=%s', array($current_if)));
        exit;
      // 當$pconfig['act']存在 並== 'toggle' and $id存在時
      // 用於切換 Rule 的狀態
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'toggle' && isset($id)) {
        // toggle item
        // 當$a_filter[$id]['disabled']存在時
        if(isset($a_filter[$id]['disabled'])) {
            unset($a_filter[$id]['disabled']); // 清除['disabled']
        } else {
            $a_filter[$id]['disabled'] = true; // 建立['disabled']
        }
        write_config();
        mark_subsystem_dirty('filter');
        $response = array("id" => $id);
        // 若沒有$a_filter[$id]['disabled']，$response["new_label"] = gettext("Disable Rule")
        // 若有$a_filter[$id]['disabled']，$response["new_label"] = gettext("Enable Rule")
        $response["new_label"] = !isset($a_filter[$id]['disabled']) ?  gettext("Disable Rule") : gettext("Enable Rule");
        // $response["new_state"] = true 或 false
        $response["new_state"] = !isset($a_filter[$id]['disabled']) ;
        echo json_encode($response);
        exit;
        // 用於log的功能切換
    } elseif (isset($pconfig['act']) && $pconfig['act'] == 'log' && isset($id)) {
        // toggle logging
        if(isset($a_filter[$id]['log'])) {
            unset($a_filter[$id]['log']); // 清除['log']
        } else {
            $a_filter[$id]['log'] = true; // 建立['log']
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

$selected_if = 'FloatingRules'; // 預設頁面
if (isset($_GET['if'])) {  // 取的目前頁面的介面名稱
    $selected_if = htmlspecialchars($_GET['if']);
}

include("head.inc");

$a_filter_raw = config_read_array('filter', 'rule'); // 取得的config_array資料
legacy_html_escape_form_data($a_filter); // 拆解array
?>
<body>
<script>
$( document ).ready(function() {
  // link delete buttons 綁定刪除按鈕點擊後動作
  $(".act_delete").click(function(event){
    // .preventDefault();停止事件的DOM預設功能，例如<a>標籤的跳頁動作
    event.preventDefault();
    var id = $(this).attr("id").split('_').pop(-1); // 使用.attr("id")取得作用按鈕id 並用.split('_')切割 取最後一位
    console.log(id);
    // 若id != 'x' 則為單獨刪除動作(例如id = del_4)
    if (id != 'x') {
      // delete single
      BootstrapDialog.show({ // 確認用彈出視窗
        type:BootstrapDialog.TYPE_DANGER, // 顏色:警訊
        title: "<?= gettext("Rules");?>", // 標題
        message: "<?=gettext("Do you really want to delete this rule?");?>", // 訊息
        // 按鈕及動作
        buttons: [{
                  label: "<?= gettext("No");?>",
                  // dialogRef = 這個彈出視窗
                  action: function(dialogRef) {
                      dialogRef.close(); // 關閉視窗
                  }}, {
                  label: "<?= gettext("Yes");?>",
                  action: function(dialogRef) {
                    $("#id").val(id); // 要刪除的id = $pconfig['id']
                    $("#action").val("del"); // 動作 = $pconfig['act']
                    $("#iform").submit() // 要提交的表格 = post提交動作
                }
              }]
    });
    } else {
      // delete selected 刪除選擇內容
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
                    $("#id").val(""); // 要刪除的id
                    $("#action").val("del_x"); // 動作
                    $("#iform").submit() // 要提交的表格
                }
              }]
      });
    }
  });

  // enable/disable selected 激活被選的Rule 按鈕
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
                  $("#action").val("toggle_enable"); // 動作 = $pconfig['act']
                  $("#iform").submit()
              }
            }]
    });
  });
  // 關閉被選的Rule 按鈕
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
                  $("#action").val("toggle_disable"); // 動作 = $pconfig['act']
                  $("#iform").submit()
              }
            }]
    });
  });

  // link move buttons 綁定移動按鈕點擊後動作
  $(".act_move").click(function(event){
    event.preventDefault();
    var id = $(this).attr("id").split('_').pop(-1); // 按鈕id範例 : 移到最底(move_6) 移至選取id之後(move_4)
    $("#id").val(id);
    $("#action").val("move"); // 動作 = $pconfig['act']
    $("#iform").submit();
  });

  // link apply buttons 綁定套用按鈕點擊後動作
  $("#btn_apply").click(function(event){
    event.preventDefault();
    $("#action").val("apply"); // 動作 = $pconfig['act']
    $("#iform").submit();
  });

  // link toggle buttons 綁定各別激活/關閉按鈕
  $(".act_toggle").click(function(event){
      event.preventDefault();
      let target = $(this);
      target.addClass('fa-spinner fa-pulse'); // 增加loding效果 icon class到點擊的icon
      let id = target.attr("id").split('_').pop(-1); // id範例: toggle_5
      $.ajax("firewall_rules.php",{ // 使用ajax的post傳值
          type: 'post',
          cache: false,
          dataType: "json",
          data: {'act': 'toggle', 'id': id}, // {'act': 'toggle'} = ($pconfig['act'] == 'toggle')
          // 傳值成功後動作
          success: function(response) {
              console.log(response);
              // 點擊後的response
              //{id: '2', new_label: 'Enable Rule', new_state: false}
              //{id: '2', new_label: 'Disable Rule', new_state: true}
              // .prop('title', response['new_label']) 修改滑過時按鈕提示文字
              target.prop('title', response['new_label']).tooltip('fixTitle').tooltip('hide');
              target.removeClass('fa-spinner fa-pulse'); // 移除loding效果 icon
              // 若response['new_state'] = true
              if (response['new_state']) {
                  // 移除Class text-muted(關閉時icon顏色)，若已有fa-play Class，增加text-success(激活時icon顏色)，若沒有增加text-danger
                  target.removeClass('text-muted').addClass(target.hasClass('fa-play') ? 'text-success' : 'text-danger');
              } else { // 若response['new_state'] = false
                  // 移除Class text-success text-danger ，增加text-muted
                  target.removeClass('text-success text-danger').addClass('text-muted');
              }
              $("#fw-alert-box").removeClass("hidden"); // 移除提示視窗(apply)的hidden class
              $(".fw-alert-messages").addClass("hidden"); // 隱藏所有提示視窗的文字
              $("#fw-alert-changes").removeClass("hidden"); // 移除提示視窗(apply)文字的hidden class
          },
          error: function () {
              // 傳值失敗移除Class fa-spinner fa-pulse
              target.removeClass('fa-spinner fa-pulse');
          
          }
      });
  });

   // link log buttons 綁定log激活/關閉按鈕
  $(".act_log").click(function(event){
      event.preventDefault();
      let target = $(this);
      // 移除激活時icon ， 增加loding效果 icon
      target.removeClass('fa-info-circle').addClass('fa-spinner fa-pulse');
      let id = target.attr("id").split('_').pop(-1);// id範例: toggle_2
      $.ajax("firewall_rules.php",{ // 使用ajax的post傳值
          type: 'post',
          cache: false,
          dataType: "json",
          data: {'act': 'log', 'id': id}, // {'act': 'log'} = ($pconfig['act'] == 'log')
          success: function(response) {
              console.log(response);
              // 點擊後的response
              // {id: '2', new_label: 'Enable Log', new_state: false}
              // {id: '2', new_label: 'Disable Log', new_state: true}
              // .prop('title', response['new_label']) 修改滑過時按鈕提示文字
              target.prop('title', response['new_label']).tooltip('fixTitle').tooltip('hide');
              // 移除loding效果 icon ， 增加log icon 
              target.removeClass('fa-spinner fa-pulse').addClass('fa-info-circle');
              // 若response['new_state'] = true
              if (response['new_state']) {
                  // 移除text-muted(關閉時icon顏色)，增加text-info(激活時icon顏色)
                  target.removeClass('text-muted').addClass('text-info');
              } else { // 若response['new_state'] = false
                  // 移除text-info，增加text-muted
                  target.removeClass('text-info').addClass('text-muted');
              }
              $("#fw-alert-box").removeClass("hidden"); // 移除提示視窗(apply)的hidden class
              $(".fw-alert-messages").addClass("hidden"); // 隱藏所有提示視窗的文字
              $("#fw-alert-changes").removeClass("hidden"); // 移除提示視窗(apply)文字的hidden class
          },
          error: function () {
              // 傳值失敗移除Class fa-spinner fa-pulse 增加log icon 
              target.removeClass('fa-spinner fa-pulse').addClass('fa-info-circle');
          }
      });
  });

  // watch scroll position and set to last known on page load
  // 從/opnsense/www/js/opnsense.js 中調用
  // 紀錄頁面最後位置，頁面重整時移動到頁面加載時的最後已知位置
  watchScrollPosition();
  console.log(window.location.href.replace(/\/|\:|\.|\?|\#/gi, ''));

  // select All 綁定選取全部按鈕
  $("#selectAll").click(function(){
      // 抓取尚未被選取的項目:not(:disabled)
      // 修改"checked"的內容為這個按鈕的"checked"內容(這按鈕是選取，那就都會是選取)
      $(".rule_select:not(:disabled)").prop("checked", $(this).prop("checked"));
  });

  // move category block
  // 暫時移除select category下拉選單
  // .detach()和.remove()一樣都是移除元素內所有內容，包含該元素，但不同的是，.detach()的元素事件仍然存在。
  // $('<p>要加入的原素</p>').appendTo('.目的地);
  $("#category_block").detach().appendTo($(".page-content-head > .container-fluid > .list-inline"));
  console.log($("#category_block").detach().appendTo($(".page-content-head > .container-fluid > .list-inline")));
  // 清除後須加回pull-right按鈕才會置右
  $("#category_block").addClass("pull-right"); 

  // 綁定檢查(inspect)按鈕
  $("#btn_inspect").click(function(){
      // .data()說明  https://www.fooish.com/jquery/data.html
      // HTML5 新增的 data-key = '30' 自定義屬性 (data attributes)
      // 透過.data(key) = '30' 來取得元素上的資料
      // 如果 data attribute 的值是 { 或 [ 開頭，jQuery 會自動當 JSON 來解析成 JavaScript Object/Array
      // <<HTML>>
      // <div data-options='{"name":"John"}'></div>
      // <<jQuery>>
      // $('div').data('options').name === 'John';
      let mode = $(this).data('mode');
      console.log(mode);
      // 如果data-mode = 'stats'
      if (mode === 'stats') {
            $(".view-stats").hide();
            $(".view-info").show();
            $(this).removeClass('active'); // 移除active
            // .data('mode', 'info') 也可用於綁定任意資料到特定元素上面。
            $(this).data('mode', 'info'); // data-mode = 'info'
      } else { // 第一次按按鈕時還沒有data-mode 參數，所以mode =undefined
               // 在這邊data-mode第一次被附值為data-mode = 'stats'
            $(".view-stats").show();
            $(".view-info").hide();
            $(this).addClass('active'); // 增加active
            $(this).data('mode', 'stats'); // data-mode = 'stats'
            // 使用ajax取得 view-stats 的資料
            // api位置\opnsense\mvc\app\controllers\OPNsense\Firewall\Api\FilterUtilController.php > class FilterUtilController > function ruleStatsAction()
            $.ajax('api/firewall/filter_util/rule_stats', {
                success: function(response) {
                console.log(response); // {status: 'ok', stats: $result}
                    if (response.status == 'ok') {
                        let fileSizeTypes = ["", "K", "M", "G", "T", "P", "E", "Z", "Y"];
                        $.each(response.stats, function(index, value) {
                            console.log(index);
                            console.log(value);
                            // 將stats中的資料依照index, value格式取出，重組為html標籤的 id 以及 內容
                            // 資料範例:
                            // index= 02f4bab031b57d1e30553ce08e0ec131
                            // value= {pf_rules: 2, evaluations: 36224, packets: 51, bytes: 5214, states: 0}
                            $("#" + index + "_evaluations").text(value.evaluations); // 取evaluations: 36224
                            $("#" + index + "_states").text(value.states); // 取states: 0
                            $("#" + index + "_packets").text(value.packets); // 取packets: 51
                            if (value.bytes > 0) { // 若bytes: 5214 > 0
                                // Math.floor(值):回傳比值大，最接近的整數
                                // Math.log()會回傳參數的自然對數
                                // Math.log(value.bytes) / Math.log(1000)，以value.bytes為底，1000的對數
                                let ndx = Math.floor(Math.log(value.bytes) / Math.log(1000));
                                console.log("ndx自然對數");
                                console.log(ndx);
                                $("#" + index + "_bytes").text(
                                    // Math.pow(base, exponent) 方法用來做指數運算，base的exponent次方
                                    // .toFixed()將一個數字轉成固定小數位數的字串(四捨五入)，(2)為取小數點後兩位
                                    (value.bytes / Math.pow(1000, ndx)).toFixed(2) + ' ' + fileSizeTypes[ndx]
                                );
                            } else { // 若bytes <= 0
                                $("#" + index + "_bytes").text("0");
                            }
                        });
                    }
                }
            });
      }
      $(this).blur(); // blur 事件型別在元素失去焦點時響應
  });

  // hook category functionality
  // 抓取防火牆類別，並綁定至Select category功能
  hook_firewall_categories();

  // expand internal auto generated rules
  // 展開內部自動生成規則
  // 當<tr>內的class internal-rule筆數>0時
  if ($("tr.internal-rule").length > 0) {
      // 顯示id expand-internal-rules物件
      $("#expand-internal-rules").show();
      // 修改id internal-rule-count物件的文字內容為("tr.internal-rule").length)
      $("#internal-rule-count").text($("tr.internal-rule").length);
  }

  // our usual zebra striping doesn't respect hidden rows, hook repaint on .opnsense-rules change() and fire initially
  // 生成斑馬紋表格效果
  $(".opnsense-rules > tbody > tr").each(function(){
      // save zebra color
      console.log("--------$(this).children(0)資料內容---------");
      console.log($(this).children(0));
      console.log("-------------------------------------------");
      let tr_color = $(this).children(0).css("background-color");
      if (tr_color != 'transparent' && !tr_color.includes('(0, 0, 0')) {
          $("#fw_category").data('stripe_color', tr_color);
      }
  });
  $(".opnsense-rules").removeClass("table-striped");
  $(".opnsense-rules").change(function(){
      $(".opnsense-rules > tbody > tr:visible").each(function (index) {
          $(this).css("background-color", "inherit");
          if ( index % 2 == 0) {
              $(this).css("background-color", $("#fw_category").data('stripe_color'));
          }
      });
  });
  //
  $("#expand-internal").click(function(event){
      event.preventDefault();
      $(".internal-rule").toggle();
      $(".opnsense-rules").change();
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
        <?php print_service_banner('firewall'); ?>
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
          !empty($config['interfaces'][$selected_if]['descr']) ?
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
                      <td class="text-nowrap">
                        <strong><?= gettext('Description') ?></strong>
                        <i class="fa fa-question-circle" data-toggle="collapse" data-target=".rule_md5_hash" ></i>
                      </td>
                      <td class="text-nowrap button-th">
                        <a href="<?= url_safe('firewall_rules_edit.php?if=%s', array($selected_if)) ?>" class="btn btn-primary btn-xs" data-toggle="tooltip" title="<?= html_safe(gettext('Add')) ?>">
                          <i class="fa fa-plus fa-fw"></i>
                        </a>
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
                plugins_firewall($fw);
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
          echo('<br/>$a_nat資料內容<br/>');
          $a_nat = &config_read_array('nat', 'rule');
          print_r ($a_nat);
          echo('<br/>$config['.'interfaces'.']資料內容<br/>');
          print_r ($config['interfaces']);
          
          $path = '/usr/local/etc/inc/plugins.inc.d/';
          $clash = '/usr/local/etc/inc/';
          $ext = '.inc';
          echo('<br/>$plugins資料內容<br/>');
          $plugins = glob($path . '*' . $ext);
          sort($plugins); // 覆蓋KEY值，由內容小到大(A~z)重新排序。
          print_r ($plugins);
          
          
          echo('<br/>plugins有function的檔名:<br/>');
          if (function_exists('ipsec_interfaces')) {
            echo ('ipsec有ipsec_interfaces<br/>');
          }else{
            echo('無');
          };
          
          if (function_exists('loopback_interfaces')) {
            echo ('loopback有loopback_interfaces<br/>');
          }else{
            echo('無');
          };

          if (function_exists('openvpn_interfaces')) {
            echo ('openvpn有openvpn_interfaces<br/>');
          }else{
            echo('無');
          };
          
          if (function_exists('pf_interfaces')) {
            echo ('pf有pf_interfaces<br/>');
          }else{
            echo('無');
          };

          echo('<br/>$intf_config = &config_read_array('.'interfaces'.', '.'lo0'.');資料內容:<br/>');
          $intf_conf = &config_read_array('interfaces', 'lo0');
          print_r ($intf_conf);
          
          echo('<br/>$pconfig資料內容:<br/>');
          $pconfig = $_POST;
          print_r ($pconfig);
          
          echo('<br/>$_GET資料內容:<br/>');
          $_GET_if = $_GET;
          print_r ($_GET_if);
          
          echo('<br/>$a_filter資料內容:<br/>');
          print_r ($a_filter);

          echo('<br/>$a_filter_raw資料內容:<br/>');
          print_r ($a_filter_raw);

          echo('<br/>$a_filter_org資料內容:<br/>');
          $a_filter_org = &config_read_array('filter', 'rule');
          print_r ($a_filter_org);
          
          echo('<br/>$stream資料內容:<br/>');
          $configdSocket = '/var/run/configd.socket';
          $errorMessage = "";
          $poll_timeout = 2;
          $stream = @stream_socket_client('unix:///var/run/configd.socket', $errorNumber, $errorMessage, $poll_timeout);
          print_r ($stream);

          echo('<br/>fwrite($stream, \'filter rule stats\');返回寫入字符:<br/>');
          $stream_fwrite = fwrite($stream, 'filter rule stats');
          print_r ($stream_fwrite);

          echo('<br/>str_replace($endOfStream, \'\', $resp);資料內容:<br/>');
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

          echo('<br/>json_decode($return, true);資料內容:<br/>');
          $result = json_decode($return, true);
          print_r ($result);

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

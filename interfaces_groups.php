<?php

/*
 * Copyright (C) 2014-2015 Deciso B.V.
 * Copyright (C) 2009 Ermal Luçi
 * Copyright (C) 2004 Scott Ullrich <sullrich@gmail.com>
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
require_once("interfaces.inc"); // 調用get_real_interface();
require_once("filter.inc");
require_once("system.inc"); // 調用system_cron_configure();

$a_ifgroups = &config_read_array('ifgroups', 'ifgroupentry'); //取config資料
// /usr/local/www/interfaces_groups.php > require_once("guiconfig.inc");
// /usr/local/www/guiconfig.inc > require_once("config.inc");
// /usr/local/etc/inc/config.inc > &config_read_array()

// 接收表格post訊息
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 若非空值 $id = $_POST['id'];
    if (!empty($a_ifgroups[$_POST['id']])) {
        $id = $_POST['id'];
    }

    if (isset($_POST['apply'])) {
        system_cron_configure(); // 從system.inc調用
        filter_configure(); // 從filter.inc調用
        clear_subsystem_dirty('filter'); // 從util.inc調用
        $savemsg = gettext('The settings have been applied and the rules are now reloading in the background.');
    } elseif (!empty($_POST['action']) && $_POST['action'] == "del" && isset($id)) {
      // 當$_POST['action']非空值、$_POST['action']=="del" 、isset($id)
        $members = explode(" ", $a_ifgroups[$id]['members']);
        // 用空白分割取得成員array
        foreach ($members as $ifs) {
            // 用要刪除的資料id取得$a_ifgroups[$id]['ifname'] 、$a_ifgroups[$id]['members']
            // 調用util.inc的mwexecf()執行cmd指令
            // 調用interfaces.inc中的get_real_interface()帶入$ifs  $ifs內容示意:[members] => wan lo0
            // mwexecf('/sbin/ifconfig %s -group %s', array('wan lo0', 'test_for_group'));
            mwexecf('/sbin/ifconfig %s -group %s', array(get_real_interface($ifs), $a_ifgroups[$id]['ifname']));
            // cmd指令  /sbin/ifconfig wan lo0 -group test_for_group
            // 經過get_real_interface()後會換成真實的interface名稱
            // /sbin/ifconfig vtnet0 -group test_for_group
            // /sbin/ifconfig lo0 -group test_for_group
            // 功能為從interface的group清單中移除group
            // /sbin/ifconfig lo0 group test_for_group *此為增加group
        }
        $pointers = [
            ['filter', 'rule'],
            ['nat', 'rule'],
            ['nat', 'onetoone'],
            ['nat', 'outbound', 'rule'],
        ];
        foreach ($pointers as $sections) {
            // call_user_func_array：把第一个参数作为回调函数进行调用，第二个参数传入数组，将数组中的值作为回调函数的参数
            // 使用call_user_func_array()調用config.inc的function &config_read_array() 帶入$sections內容
            $ref = &call_user_func_array('config_read_array', $sections); 
            if (!empty($ref)) {
                // &call_user_func_array('config_read_array', $sections); 內容:
                // [0] => Array ( [@attributes] => Array ( [uuid] => 401a19cd-53fe-4387-b5d1-305ced7a32d5 ) [type] => pass [ipprotocol] => inet [descr] => Default allow LAN to any rule [interface] => lan [source] => Array ( [network] => lan ) [destination] => Array ( [any] => ) ) 
                // [1] => Array ( [@attributes] => Array ( [uuid] => 02cf1f41-bd87-40d4-9446-d5eec543d857 ) [type] => pass [ipprotocol] => inet6 [descr] => Default allow LAN IPv6 to any rule [interface] => lan [source] => Array ( [network] => lan ) [destination] => Array ( [any] => ) )
                // $x = Key / $rule = Value
                foreach ($ref as $x => $rule) {
                    // [interface] => lan
                    if ($rule['interface'] == $a_ifgroups[$id]['ifname']) {
                      unset($ref[$x]); // 清除該筆變數資料
                    }
                }
            }
        }
        unset($a_ifgroups[$id]); // 清除變數資料
        write_config(); // 從config.inc調用,將跟新後config寫入?
        header(url_safe('Location: /interfaces_groups.php')); // 轉跳回group頁面 
        exit;
    }
}

legacy_html_escape_form_data($a_ifgroups);

include("head.inc");

?>

<body>
  <script>
    // 刪除按鈕動作設定
  $( document ).ready(function() {
    // link delete buttons
    $(".act_delete").click(function(event){
      event.preventDefault(); // 取消事件的預設行為
      var id = $(this).data("id"); // 取要刪除的資料id
      var alldata = $(this).data(); // {id: 0, toggle: 'tooltip', bs.tooltip: m}
      console.log(alldata);
      // delete single，BootstrapDialog.show 為Bootstrap自定義彈出視窗 更多:https://www.cnblogs.com/zzwlong/p/8509085.html
      BootstrapDialog.show({
        type:BootstrapDialog.TYPE_DANGER,
        //BootstrapDialog.TYPE_DEFAULT,   
        //BootstrapDialog.TYPE_INFO,   
        //BootstrapDialog.TYPE_PRIMARY,   
        //BootstrapDialog.TYPE_SUCCESS,   
        //BootstrapDialog.TYPE_WARNING,   
        //BootstrapDialog.TYPE_DANGER];

        // title: "<?= gettext("Group");?>",
        title: "<?= gettext("Group");?>",
        message: "<?=gettext("Do you really want to delete this group? All elements that still use it will become invalid (e.g. filter rules)!");?>",
        buttons: [{
                  label: "<?= gettext("No");?>",
                  // dialogRef = 這個彈出視窗
                  action: function(dialogRef) {
                      dialogRef.close(); // 關閉視窗
                  }}, {
                  label: "<?= gettext("Yes");?>",
                  action: function(dialogRef) {
                    $("#id").val(id); // 要刪除的id
                    $("#action").val("del"); // 動作
                    $("#iform").submit() // 要提交的表格
                }
              }]
      });
    });

  });
  </script>
  <!-- 導入head -->
<?php include("fbegin.inc"); ?> 
  <section class="page-content-main">
    <div class="container-fluid">
      <div class="row">
        <!-- 套用的提示訊息 -->
        <?php print_service_banner('firewall'); ?>
        <!-- $savemsg = 儲存成功的顯示訊息 -->
        <?php if (isset($savemsg)) print_info_box($savemsg); ?> 
        <?php if (is_subsystem_dirty('filter')): ?><p>
        <?php print_info_box_apply(gettext("The firewall rule configuration has been changed.<br />You must apply the changes in order for them to take effect."));?>
        <?php endif; ?>
        <!-- 套用的提示訊息end -->
        <section class="col-xs-12">
          <div class="tab-content content-box col-xs-12">
            <form  method="post" name="iform" id="iform">
              <!-- 刪除時使用的表格input -->
              <input type="hidden" id="action" name="action" value="">
              <input type="hidden" id="id" name="id" value="">
              <!-- 刪除時使用的表格input end -->
              <table class="table table-striped">
                <thead>
                  <tr>
                    <th><?=gettext("Name");?></th>
                    <th><?=gettext("Members");?></th>
                    <th><?=gettext("Description");?></th>
                    <!-- 新增按鈕 -->
                    <th class="text-nowrap">
                      <a href="interfaces_groups_edit.php" class="btn btn-primary btn-xs" data-toggle="tooltip" title="<?= html_safe(gettext('Add')) ?>">
                        <i class="fa fa-plus fa-fw"></i>
                      </a>
		                </th>
                  </tr>
                </thead>
                <tbody>
<?php
                $i = 0;
                // $a_ifgroupsㄔ資料內容示意:
                // Array ( 
                //  [0] => Array ( [members] => lo0 [descr] => test [ifname] => group ) 
                //  [1] => Array ( [members] => wan lo0 [descr] => test_for_group txt [ifname] => test_for_group ) 
                // )
                print_r ($a_ifgroups);

                // mwexecf() 與 get_real_interface()資料內容示意:
                $mbers = explode(" ", $a_ifgroups[1]['members']);
                print_r ($mbers);
                // echo (get_real_interface($mbers));

                foreach ($mbers as $ifs) {
                  // $mber = get_real_interface($ifs);
                  echo (sprintf('/sbin/ifconfig %s -group %s', get_real_interface($ifs), $a_ifgroups[1]['ifname']).'/n');
                }
                echo('<br/>');
                // &config_read_array()資料內容示意:
                $point = [
                  ['filter', 'rule'],
                  ['nat', 'rule'],
                  ['nat', 'onetoone'],
                  ['nat', 'outbound', 'rule'],
                ];

                foreach ($point as $section) {
                  // call_user_func_array：把第一个参数作为回调函数进行调用，第二个参数传入数组，将数组中的值作为回调函数的参数
                  // 使用call_user_func_array()調用config.inc的function &config_read_array() 帶入$sections內容
                  $refff = &call_user_func_array('config_read_array', $section); 
                  
                  // if (!empty($ref)) {
                  //     foreach ($ref as $x => $rule) {
                  //         if ($rule['interface'] == $a_ifgroups[$id]['ifname']) {
                  //           unset($ref[$x]);
                  //         }
                  //     }
                  // }
                }
                print_r ($refff);



                // name欄位
                foreach ($a_ifgroups as $ifgroupentry): ?>
                  <tr>
                    <td>
                    <!-- 鏈接範例:  https://130.211.251.29/firewall_rules.php?if=test_for_group -->
                      <a href="/firewall_rules.php?if=<?=$ifgroupentry['ifname'];?>"><?=$ifgroupentry['ifname'];?></a>
                    </td>
                    <td>
<?php
                    // member欄位 foreach取所有成員
                    $iflist = legacy_config_get_interfaces();
                    foreach (explode(" ", $ifgroupentry['members']) as $id => $memb):?>
                      <?=$id > 0 ? "," : "";?>
                      <?=!empty($iflist[$memb]) ? $iflist[$memb]['descr'] : $memb;?>
<?php
                    endforeach;?>
                    </td>
                    <!-- descr欄位 -->
                    <td><?=$ifgroupentry['descr'];?></td>
                    <!-- 編輯欄位 -->
                    <td class="text-nowrap">
                      <!-- 編輯鏈接範例:  https://130.211.251.29/interfaces_groups_edit.php?id=0 -->
                      <a href="interfaces_groups_edit.php?id=<?=$i;?>" class="btn btn-xs btn-default" data-toggle="tooltip" title="<?= html_safe(gettext('Edit')) ?>">
                        <i class="fa fa-pencil fa-fw"></i>
                      </a>
                      <!-- 刪除按鈕 -->
                      <button title="<?= html_safe(gettext('Delete')) ?>" data-toggle="tooltip" data-id="<?=$i;?>" class="btn btn-default btn-xs act_delete" type="submit">
                        <i class="fa fa-trash fa-fw"></i>
                      </button>
                    </td>
                  </tr>
<?php
                $i++;
                endforeach; ?>
                  <tr>
                    <!-- 表格下方說明文 -->
                    <td colspan="4">
                      <?=gettext("Interface Groups allow you to create rules that apply to multiple interfaces without duplicating the rules. If you remove members from an interface group, the group rules no longer apply to that interface.");?>
                    </td>
                  </tr>
                </tbody>
              </table>
            </form>
          </div>
        </section>
      </div>
    </div>
  </section>

<?php include("foot.inc"); ?>

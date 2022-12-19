<?php

/*
 * Copyright (C) 2014-2015 Deciso B.V.
 * Copyright (C) 2012 Jim Pingle <jimp@pfsense.org>
 * Copyright (C) 2007-2008 Scott Ullrich <sullrich@gmail.com>
 * Copyright (C) 2005-2006 Colin Smith <ethethlay@gmail.com>
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

$aclObj = new \OPNsense\Core\ACL();

/* display a top alert bar if need be */
// $need_alert_display = false;
// $found_notices = are_notices_pending();
// if($found_notices == true) {
//     $notices = get_notices();
//     if(!$notices) {
//         $need_alert_display = true;
//         $display_text = print_notices($notices) . "<br />";
//     }
// }
// if($need_alert_display == true) {
//     echo "<div class=\"col-xs-12\"><div class=\"alert alert-info\"><p>".$display_text."</p></div></div>";
// }

?>

<header class="page-head">
  <nav class="navbar navbar-default">
    <div class="container-fluid">
      <div class="navbar-header">
        <a class="navbar-brand" href="/index.php">
<?php if (file_exists("/usr/local/opnsense/www/themes/{$themename}/build/images/uguard-web-14.png")): ?>
        <img class="brand-logo" src="<?= cache_safe("/ui/themes/{$themename}/build/images/uguard-web-14.png") ?>" height="30" alt="logo" />
<?php else: ?>
        <img class="brand-logo" src="<?= cache_safe("/ui/themes/{$themename}/build/images/uguard-web-14.png") ?>" height="30" alt="logo" />
<?php endif ?>
<?php if (file_exists("/usr/local/opnsense/www/themes/{$themename}/build/images/uguard-web-15.png")): ?>
        <img class="brand-icon" src="<?= cache_safe("/ui/themes/{$themename}/build/images/uguard-web-15.png") ?>" height="30" alt="icon" />
<?php else: ?>
        <img class="brand-icon" src="<?= cache_safe("/ui/themes/{$themename}/build/images/uguard-web-15.png") ?>" height="30" alt="icon" />
<?php endif ?>
        </a>
        <button type="button" class="wrapper collapsed" data-toggle="collapse" data-target="#navigation">
          <span class="sr-only">Toggle navigation</span>
          <span class="icon-bar nenu-top bar bar-top"></span>
          <span class="icon-bar middle bar bar-middle"></span>
          <span class="icon-bar bottom bar bar-bottom"></span>
        </button>
      </div>
      <button class="toggle-sidebar" data-toggle="tooltip right" title="<?= html_safe(gettext('Toggle sidebar')) ?>" style="display:none"><i class="fa fa-chevron-left"></i></button>
      <div class="collapse navbar-collapse">
        <ul class="nav navbar-nav navbar-right">
          <li>
            <form class="navbar-form" role="search">
              <div class="input-group">
                <div class="search-input-left input-group-addon"><i class="fa fa-search"></i></div>
                <input type="text" style="width: 250px;" class="search-input-right form-control" tabindex="1" data-provide="typeahead" id="menu_search_box" autocomplete="off">
              </div>
            </form>
          </li>
          <li id="menu_messages"><?= get_menu_messages() ?></li>
          <!-- <li id="menu_messages"><span class="navbar-text">root@UGuard.localdomain</span></li> -->
          <!-- Log Out/password -->
          <li>
            <div id="mobile_only_nav" class="mobile-only-nav pull-right">
              <ul class="nav navbar-right top-nav pull-right">
                <li class="dropdown auth-drp">
                  <a href="#" class="dropdown-toggle pr-0" data-toggle="dropdown"><img style="width: 30px;" src="<?= cache_safe("/ui/themes/{$themename}/build/images/user-02.jpg") ?>" alt="user_auth" class="user-auth-img img-circle"/><span class="user-online-status"></span></a>
                  <ul class="dropdown-menu user-auth-dropdown" data-dropdown-in="flipInX" data-dropdown-out="flipOutX">
                    <li>
                      <a href="/system_usermanager_passwordmg.php"><i class="zmdi zmdi-settings"></i><span></i><?=gettext("Password");?></span></a>
                    </li>
                    <li>
                      <a href="/index.php?logout"><i class="zmdi zmdi-power"></i><span><?=gettext("Log Out");?></span></a>
                    </li>
                    <li class="divider"></li>
                      <li class="sub-menu show-on-hover">
                          <a href="#" class="dropdown-toggle pr-0 level-2-drp"><i class="zmdi zmdi-check text-success"></i><?=gettext("Language");?></a>
                          <ul class="dropdown-menu open-left-side">
<?php

require_once("guiconfig.inc");
require_once("system.inc");


if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $lang_config = array();

    if (isset($_GET['savemsg'])) {
        $savemsg = htmlspecialchars(gettext($_GET['savemsg']));
    }

	  $lang_config['language'] = $config['system']['language'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pconfig = $_POST;

    $config['system']['language'] = $pconfig['language'];
    write_config();
    header(url_safe('Location: #', array('The changes have been applied successfully.')));
    exit;
}

?>
<?php
                            // 從system.inc調用get_locale_list() 取語言清單，例如:$locales['en_US'] = gettext('English');
                            foreach (get_locale_list() as $lcode => $ldesc):?>
                              <li <?= $lcode == $lang_config['language'] ? "class=\"language_on\"": "" ; ?> >
                                <form method="post" name="<?=$lcode."_form";?>" id="<?=$lcode."_form";?>">
                                  <input name="language" type="text" value="<?=$lcode;?>" class="hide"/>
                                  <input name="<?=$lcode."_Submit";?>" type="submit" class="btn btn-primary zmdi zmdi-check" value="<?=html_safe(gettext($ldesc));?>" />
                                </form>  
                              </li>
<?php
                            endforeach;?>
				  
                          </ul>	
                      </li>
                    <li class="divider"></li>
                  </ul>
                </li>
              </ul>
            </div>	
          </li>
          <!-- Log Out/password -->
        </ul>
      </div>
    </div>
  </nav>
</header>

<main class="page-content col-sm-9 col-sm-push-3 col-lg-10 col-lg-push-2">
    <aside id="navigation" class="page-side col-xs-12 col-sm-3 col-lg-2 hidden-xs">
        <div class="row testgui">
            <nav class="page-side-nav">
                <div id="mainmenu" class="panel" style="border:0px" >
                    <div class="panel list-group" style="border:0px">
<?php
                          foreach($menuSystem as $topMenuItem): ?>
<?php
                          if (count($topMenuItem->Children) >= 1): ?>
                            <!-- 最外層 -->
                            <a href="#<?=$topMenuItem->Id;?>" class="list-group-item <?= $topMenuItem->Selected ? 'active-menu-title' : ''; ?>" data-toggle="collapse" data-parent="#mainmenu"><span class="<?=$topMenuItem->CssClass;?> __iconspacer"></span><?=html_safe(gettext($topMenuItem->VisibleName));?>  </a>
                            <!-- 第二層 -->
                            <div class="collapse <?=$topMenuItem->Selected ? 'active-menu in' :'';?>" id="<?=$topMenuItem->Id;?>">
<?php
                            foreach($topMenuItem->Children as $subMenuItem): ?>
<?php
                              if ($subMenuItem->Url == '' ):?>
                              <!-- 非url生成 -->
                              <!-- 第三層 -->
                               <a href="#<?=$topMenuItem->Id;?>_<?=$subMenuItem->Id;?>" 
                                  class="menu-a-radius list-group-item <?=$subMenuItem->Selected ? "active-menu-title" : '';?> <?=($subMenuItem->Id) == "DHCPv4" ? "hide" : '';?> <?=($subMenuItem->Id) == "DHCPv6" ? "hide" : '';?>" 
                                  data-toggle="collapse" data-parent="#<?=$topMenuItem->Id;?>" aria-expanded="<?=$subMenuItem->Selected ? "true" : "false";?>">
                                  <div style="display: table;width: 90%;">
                                    <div style="display: table-row">
                                      <div style="display: table-cell"><?=html_safe(gettext($subMenuItem->VisibleName));?></div>
                                        <div style="display: table-cell; text-align:right; vertical-align:middle;"><span class="<?=$subMenuItem->CssClass;?>"></span></div>
                                      </div>
                                  </div>
                               </a>
                               <!-- 第四層 -->
                               <div class="collapse <?=$subMenuItem->Selected ? "active-menu in" :'';?>" id="<?=$topMenuItem->Id;?>_<?=$subMenuItem->Id;?>">
<?php
                                  foreach ($subMenuItem->Children as $subsubMenuItem):?>
<?php
                                    if ($subsubMenuItem->IsExternal == "Y"):?>
                                            <a href="<?=$subsubMenuItem->Url;?>" target="_blank" rel="noopener noreferrer" class="font-8px menu-a-a list-group-item menu-level-3-item <?=$subsubMenuItem->Selected ? 'active' :'';?>"><?=html_safe(gettext($subsubMenuItem->VisibleName));?></a>
<?php
                                    elseif ($aclObj->isPageAccessible($_SESSION['Username'],$subsubMenuItem->Url)):?>
                                            <a href="<?=$subsubMenuItem->Url;?>" class="font-8px menu-a-a list-group-item menu-level-3-item <?=$subsubMenuItem->Selected ? 'active' :'';?>"><?=html_safe(gettext($subsubMenuItem->VisibleName));?></a>
<?php
                                    endif;
                                  endforeach;?>
                                </div>
<?php
                              elseif ($subMenuItem->IsExternal == "Y" ):?>
                              <!-- url生成 -->
                                <!-- 第三層 -->
                                <a href="<?=$subMenuItem->Url;?>" target="_blank" rel="noopener noreferrer" 
                                  class="menu-a-radius list-group-item <?=$subMenuItem->Selected ? 'active' : '';?> <?=($subMenuItem->Url) == "/system_usermanager_passwordmg.php" ? "hide" : '';?> " 
                                  aria-expanded="<?=$subMenuItem->Selected ? 'true' : 'false';?>">
                                  <div style="display: table;width: 90%;">
                                    <div style="display: table-row">
                                      <div style="display: table-cell"><?=html_safe(gettext($subMenuItem->VisibleName));?></div>
                                        <div style="display: table-cell; text-align:right; vertical-align:middle;"><span class="<?=$subMenuItem->CssClass;?>"></span></div>
                                      </div>
                                  </div>
                                </a>
<?php
                              elseif ($aclObj->isPageAccessible($_SESSION['Username'],$subMenuItem->Url)):?>
                                <a href="<?=$subMenuItem->Url;?>" 
                                  class="menu-a-radius list-group-item <?=$subMenuItem->Selected ? 'active' :'';?> <?=($subMenuItem->Url) == "/system_usermanager_passwordmg.php" ? "hide" : '';?> ">
                                  <div style="display: table;width: 90%;">
                                    <div style="display: table-row">
                                      <div style="display: table-cell"><?=html_safe(gettext($subMenuItem->VisibleName));?></div>
                                        <div style="display: table-cell; text-align:right; vertical-align:middle;"><span class="<?=$subMenuItem->CssClass;?>"></span></div>
                                    </div>
                                  </div>
                                </a>

<?php
                              endif;?>
<?php
                            endforeach; ?>
                            </div>
<?php
                          else: ?>
<?php
                              if ($topMenuItem->IsExternal == "Y" ):?>
                                <a href="<?=$topMenuItem->Url;?>" target="_blank" rel="noopener noreferrer" class="menu-a-radius list-group-item <?=$topMenuItem->Selected ? 'active-menu-title' : '';?>" data-parent="#mainmenu">
                                    <span class="<?=$topMenuItem->CssClass;?> __iconspacer"></span><?=html_safe(gettext($topMenuItem->VisibleName));?>
                                </a>
<?php
                              elseif ($aclObj->isPageAccessible($_SESSION['Username'],$topMenuItem->Url)):?>
                                <a href="<?=$topMenuItem->Url;?>" class="menu-a-radius list-group-item <?=$topMenuItem->Selected ? 'active-menu-title' : '';?>" data-parent="#mainmenu">
                                    <span class="<?=$topMenuItem->CssClass;?> __iconspacer"></span><?=html_safe(gettext($topMenuItem->VisibleName));?>
                                </a>

<?php
                              endif;?>
<?php
                        endif;?>
<?php
                        endforeach; ?>
                    </div>
                </div>
            </nav>
        </div>
    </aside>
  <div class="row">
    <header class="page-content-head">
      <div class="container-fluid">
        <ul class="list-inline">
          <li class="pb-10"><h1><?= html_safe(gentitle($menuBreadcrumbs)) ?></h1></li>
          <li class="btn-group-container">
            <form method="post">
              <?php
              if (isset($service_hook)) {
                $ssvc = service_by_name($service_hook);
                if (!empty($ssvc)) {
                  echo service_control_icon($ssvc);
                  echo service_control_links($ssvc);
                }
              } ?>

              <?php if (isset($widgetCollection)): ?>
                <a href="#" id="updatepref" style="display:none" onclick="return updatePref();" class="btn btn-primary"><?=gettext("Save Settings");?></a>
                <button id="add_widget_btn" type="button" class="btn btn-default" data-toggle="modal" data-target="#modal_widgets"><i class="fa fa-plus-circle fa-fw"></i> <?= gettext('Add widget') ?></button>
                <select class="selectpicker" data-width="120px" id="column_count">
                    <option value="1" <?=$pconfig['column_count'] == "1" ? 'selected="selected"' : '';?>><?= gettext('1 column');?></option>
                    <option value="2" <?=$pconfig['column_count'] == "2" ? 'selected="selected"' : '';?>><?= sprintf(gettext('%s columns'), '2') ?></option>
                    <option value="3" <?=$pconfig['column_count'] == "3" ? 'selected="selected"' : '';?>><?= sprintf(gettext('%s columns'), '3') ?></option>
                    <option value="4" <?=$pconfig['column_count'] == "4" ? 'selected="selected"' : '';?>><?= sprintf(gettext('%s columns'), '4') ?></option>
                    <option value="6" <?=$pconfig['column_count'] == "6" ? 'selected="selected"' : '';?>><?= sprintf(gettext('%s columns'), '6') ?></option>
                </select>
              <?php endif; ?>
             </form>
          </li>
        </ul>
      </div>
    </header>

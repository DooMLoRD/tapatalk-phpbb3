<?php
defined('IN_MOBIQUO') or exit;
require($phpbb_root_path . 'includes/functions_user.' . $phpEx);
$_COOKIE = array();
$user->session_begin();
$auth->acl($user->data);
$user->setup('ucp');

function sign_in_func()
{
    global $config, $db, $user, $auth, $template, $phpbb_root_path, $phpEx,$user_info;
	if ($config['require_activation'] == USER_ACTIVATION_DISABLE)
	{
		trigger_error('UCP_REGISTER_DISABLE');
	}
	
	include($phpbb_root_path . 'includes/functions_profile_fields.' . $phpEx);

	$user_lang		= request_var('lang', $user->lang_name);

	
	$cp = new custom_profile();
	$verify_result = false;
	$error = array();
	$is_dst = $config['board_dst'];
	$timezone = $config['board_timezone'];
	
	$token = trim($_POST['token']);
	$code = trim($_POST['code']);
	$username = trim($_POST['username']);
	$password = trim($_POST['password']);
	$post_email = trim($_POST['email']);
	$status = '';
	if(isset($token) && isset($code))
	{
	    $result = tt_register_verify($token, $code);
		if($result->result && !empty($result->email))
		{
			$email = $result->email;
		    if(!empty($post_email) && $post_email != $email)
			{
				$status = 3;
			}
			else if($user_info = tt_get_user_by_email($email))
			{
				if(!empty($username) && $username != $user_info['username'])
				{
					$status = 3;
				}
				else 
				{
					return tt_login_success();
				}		
			}
			else if(!empty($username) && !empty($email))
			{
				$data = array(
					'username'			=> utf8_normalize_nfc(request_var('username', '', true)),
					'new_password'		=> request_var('password', '', true),
					'password_confirm'	=> request_var('password', '', true),
					'email'				=> strtolower($email),
					'email_confirm'		=> strtolower($email),
					'lang'				=> basename(request_var('lang', $user->lang_name)),
					'tz'				=> request_var('tz', (float) $timezone),
				);
				
				//check username 
				if($result_username = validate_username($username))
				{
					if($result_username == 'USERNAME_TAKEN')
					{
						$status = 1;
					}
					else 
					{
						$error[] = (empty($user->lang[$result_username . '_' . strtoupper('username')])) ? $result_username : $result_username . '_' . strtoupper('username');
					}
				}
				else 
				{
					$error = validate_data($data, array(
						'new_password'		=> array(
							array('string', false, $config['min_pass_chars'], $config['max_pass_chars']),
							array('password')),
						'password_confirm'	=> array('string', false, $config['min_pass_chars'], $config['max_pass_chars']),
						'email'				=> array(
							array('string', false, 6, 60),
							array('email')),
						'email_confirm'		=> array('string', false, 6, 60),
						'tz'				=> array('num', false, -14, 14),
						'lang'				=> array('language_iso_name'),
					));
					
					// Replace "error" strings with their real, localised form
					$error = preg_replace('#^([A-Z_]+)$#e', "(!empty(\$user->lang['\\1'])) ? \$user->lang['\\1'] : '\\1'", $error);
					// DNSBL check
					if ($config['check_dnsbl'])
					{
						if (($dnsbl = $user->check_dnsbl('register')) !== false)
						{
							$error[] = sprintf($user->lang['IP_BLACKLISTED'], $user->ip, $dnsbl[1]);
						}
					}
				
					
					if (!sizeof($error))
					{
				
						// Which group by default?
						$group_name = 'REGISTERED';
				
						$sql = 'SELECT group_id
							FROM ' . GROUPS_TABLE . "
							WHERE group_name = '" . $db->sql_escape($group_name) . "'
								AND group_type = " . GROUP_SPECIAL;
						$result = $db->sql_query($sql);
						$row = $db->sql_fetchrow($result);
						$db->sql_freeresult($result);
				
						if (!$row)
						{
							trigger_error('NO_GROUP');
						}
				
						$group_id = $row['group_id'];
						$user_type = USER_NORMAL;
						$user_actkey = '';
						$user_inactive_reason = 0;
					    $user_inactive_time = 0;
				
						$user_row = array(
							'username'				=> $data['username'],
							'user_password'			=> phpbb_hash($data['new_password']),
							'user_email'			=> $data['email'],
							'group_id'				=> (int) $group_id,
							'user_timezone'			=> (float) $data['tz'],
							'user_dst'				=> $is_dst,
							'user_lang'				=> $data['lang'],
							'user_type'				=> $user_type,
							'user_actkey'			=> $user_actkey,
							'user_ip'				=> $user->ip,
							'user_regdate'			=> time(),
							'user_inactive_reason'	=> $user_inactive_reason,
							'user_inactive_time'	=> $user_inactive_time,
						);
						
						if ($config['new_member_post_limit'])
						{
							$user_row['user_new'] = 1;
						}
					
						// Register user...
						$user_id = user_add($user_row);
				
						// This should not happen, because the required variables are listed above...
						if ($user_id === false)
						{
							trigger_error('NO_USER', E_USER_ERROR);
						}
						else 
						{
							$user_info['user_id'] = $user_id;
							return tt_login_success();
						}
						
					}
					else 
					{
						foreach ($error as $msg)
						{
							trigger_error($msg);
						}
					}
				}
			}
			else 
			{
				$status = 2;
			}
		}
		else if(!$result->result)
		{
			trigger_error("Tapatalk ID verify faile!");
		}

		if(!empty($status))
		{
			$response = new xmlrpcval(array(
		        'result'            => new xmlrpcval(0, 'boolean'),
		        'result_text'       => new xmlrpcval('', 'base64'),
			 	'status'          => new xmlrpcval($status, 'string'),
			 ), 'struct');
			return new xmlrpcresp($response);
		}
	}
	else
	{
		trigger_error("Invlaid params!");
	}	
}

function tt_login_success()
{
	global $config, $db, $user, $phpbb_root_path, $phpEx,$user_info,$auth;
	header('Set-Cookie: mobiquo_a=0');
    header('Set-Cookie: mobiquo_b=0');
    header('Set-Cookie: mobiquo_c=0');
	$result = $user->session_create($user_info['user_id'], 0, true, 1);
	if($result)
	{
		$usergroup_id = array();
        $auth->acl($user->data);
        //add tapatalk_users here,for push service
        if(push_table_exists())
        {
        	global $table_prefix;
        	$sql = "SELECT * FROM " . $table_prefix . "tapatalk_users where userid = '".$user->data['user_id']."'";
	        $result = $db->sql_query($sql);
	        $userInfo = $db->sql_fetchrow($result);
	        $db->sql_freeresult($result);
	        $time = time();
        	if(empty($userInfo))
        	{
	        	$sql_data[$table_prefix . "tapatalk_users"]['sql'] = array(
	        		'userid' => $user->data['user_id'],
	        		'announcement' => 1,
	        		'pm' => 1,
	        		'subscribe' => 1,
	        		'quote' => 1,
	        		'tag' => 1,
	        		'newtopic' => 1,
	        		'updated' => time()
	        	);
	        	$sql = 'INSERT INTO ' . $table_prefix . "tapatalk_users" . ' ' .
				$db->sql_build_array('INSERT', $sql_data[$table_prefix . "tapatalk_users"]['sql']);
				$db->sql_query($sql);    	
	        }
        }
        
        // Compatibility with mod NV who was here
        if (file_exists($phpbb_root_path . 'includes/mods/who_was_here.' . $phpEx))
        {
            include_once($phpbb_root_path . 'includes/mods/who_was_here.' . $phpEx);
            if (class_exists('phpbb_mods_who_was_here') && method_exists('phpbb_mods_who_was_here', 'update_session'))
            {
                @phpbb_mods_who_was_here::update_session();
            }
        }
        
        if ($config['max_attachments'] == 0) $config['max_attachments'] = 100;
    
	    $usergroup_id[] = new xmlrpcval($user->data['group_id']);
	    $can_readpm = $config['allow_privmsg'] && $auth->acl_get('u_readpm') && ($user->data['user_allow_pm'] || $auth->acl_gets('a_', 'm_') || $auth->acl_getf_global('m_'));
	    $can_sendpm = $config['allow_privmsg'] && $auth->acl_get('u_sendpm') && ($user->data['user_allow_pm'] || $auth->acl_gets('a_', 'm_') || $auth->acl_getf_global('m_'));
	    $can_upload = ($config['allow_avatar_upload'] && file_exists($phpbb_root_path . $config['avatar_path']) && (function_exists('phpbb_is_writable') ? phpbb_is_writable($phpbb_root_path . $config['avatar_path']) : 1) && $auth->acl_get('u_chgavatar') && (@ini_get('file_uploads') || strtolower(@ini_get('file_uploads')) == 'on')) ? true : false;
	    $can_search = $auth->acl_get('u_search') && $auth->acl_getf_global('f_search') && $config['load_search'];
	    $can_whosonline = $auth->acl_gets('u_viewprofile', 'a_user', 'a_useradd', 'a_userdel');
	    $max_filesize   = ($config['max_filesize'] === '0' || $config['max_filesize'] > 10485760) ? 10485760 : $config['max_filesize'];
	    $userPushType = array();
	    $push_type = array();
	    if(file_exists("push_hook.php"))
	    {
	    	require_once 'push_hook.php';
	    	$userPushType = tt_get_user_push_type($user->data['user_id']);
	    }
	 	foreach ($userPushType as $name=>$value)
	    {
	    	$push_type[] = new xmlrpcval(array(
	            'name'  => new xmlrpcval($name,'string'),
	    		'value' => new xmlrpcval($value,'boolean'),                    
	            ), 'struct');
	    }
	    $response = new xmlrpcval(array(
	        'result'        => new xmlrpcval(true, 'boolean'),
	        'user_id'       => new xmlrpcval($user->data['user_id'], 'string'),
	        'username'      => new xmlrpcval($user->data['username'], 'base64'),
	    	'email'         => new xmlrpcval($user->data['user_email'], 'base64'),
			'user_type'     => check_return_user_type($user->data['username']),
	        'usergroup_id'  => new xmlrpcval($usergroup_id, 'array'),
	        'icon_url'      => new xmlrpcval(get_user_avatar_url($user->data['user_avatar'], $user->data['user_avatar_type']), 'string'),
	        'post_count'    => new xmlrpcval($user->data['user_posts'], 'int'),
	        'can_pm'        => new xmlrpcval($can_readpm, 'boolean'),
	        'can_send_pm'   => new xmlrpcval($can_sendpm, 'boolean'),
	        'can_moderate'  => new xmlrpcval($auth->acl_get('m_') || $auth->acl_getf_global('m_'), 'boolean'),
	        'max_attachment'=> new xmlrpcval($config['max_attachments'], 'int'),
	        'max_png_size'  => new xmlrpcval($max_filesize, 'int'),
	        'max_jpg_size'  => new xmlrpcval($max_filesize, 'int'),
	        'can_search'    => new xmlrpcval($can_search, 'boolean'),
	        'can_whosonline'    => new xmlrpcval($can_whosonline, 'boolean'),
	        'can_upload_avatar' => new xmlrpcval($can_upload, 'boolean'),
	    	'push_type'         => new xmlrpcval($push_type, 'array'),
	    ), 'struct');
	    
	    return new xmlrpcresp($response);
	}
	
	
	
}



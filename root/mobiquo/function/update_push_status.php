<?php
/**
*
* @copyright (c) 2009, 2010, 2011 Quoord Systems Limited
* @license http://opensource.org/licenses/gpl-2.0.php GNU Public License (GPLv2)
*
*/

defined('IN_MOBIQUO') or exit;
function update_push_status_func($xmlrpc_params)
{
	global $db, $auth, $user, $config,$table_prefix;
	$params = php_xmlrpc_decode($xmlrpc_params);
	if(!empty($params[1]) && !empty($params[2]) && empty($user->data['is_registered']))
	{
		$user->setup('ucp');
	    
	    $username = $params[1];
	    $password = $params[2];
	    $viewonline =  1;
	    set_var($username, $username, 'string', true);
	    set_var($password, $password, 'string', true);
	    header('Set-Cookie: mobiquo_a=0');
	    header('Set-Cookie: mobiquo_b=0');
	    header('Set-Cookie: mobiquo_c=0');
	    $auth->login($username, $password, true, $viewonline);	
	}
	if($user->data['is_registered'] == 1)
	{
		$board_url = generate_board_url();
		$data = array(
            'url'  => $board_url,
            'key'  => isset($config['tapatalk_push_key']) ? $config['tapatalk_push_key'] : '',
            'uid'  => $user->data['user_id'],
            'data' => base64_encode(serialize($params[0])),
        );
            
        $url = 'https://directory.tapatalk.com/au_update_push_setting.php';
        getContentFromRemoteServer($url, 0, $error_msg, 'POST', $data);
		return new xmlrpcresp(new xmlrpcval(true, 'boolean'));
		
	}
	return new xmlrpcresp(new xmlrpcval(false, 'boolean'));
}
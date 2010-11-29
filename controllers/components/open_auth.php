<?php
/**
 * OpenID Authentication component
 *
 * Manages user logins and permissions with support for OpenID.
 *
 * PHP version 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @version	  1.0
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       openid
 * @subpackage    openid.controller.components
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

set_include_path(get_include_path() . ':' . VENDORS . ':' . APP . 'vendors' . DS);

if (!defined('Auth_OpenID_RAND_SOURCE')) {
    define('Auth_OpenID_RAND_SOURCE', null);
}

App::import('Core', 'Email');
App::import('Component', 'Auth');
App::import('Vendor', 'Auth_OpenID', array('file' => 'Auth'.DS.'OpenID.php'));
App::import('Vendor', 'Auth_OpenID_Consumer', array('file' => 'Auth'.DS.'OpenID' . DS . 'Consumer.php'));
App::import('Vendor', 'Auth_OpenID_FileStore', array('file' => 'Auth'.DS.'OpenID' . DS . 'FileStore.php'));
App::import('Vendor', 'Auth_OpenID_SReg', array('file' => 'Auth'.DS.'OpenID' . DS . 'SReg.php'));

/**
 * OpenID Authentication control component class
 *
 * Binds access control with user authentication and session management.
 *
 * @package       openid
 * @subpackage    openid.controller.components
 */
class OpenAuthComponent extends AuthComponent {
/**
 * Information about if and how to attach an ID when user logs in with OpenID.
 * Can be:
 * - 'hash': then a hash is created out of the OpenID URL for the user
 * - 'UUID': then a UUID is generated
 * - any other string or numeric value: is used as the ID
 * - false or an empty value: no ID is added
 *
 * @var mixed
 */
	public $attachId = false;
/**
 * Controller action where the OpenID server will return control.
 * Leave empty to use $loginAction.
 *
 * @var array
 */
	public $callbackAction = null;
/**
 * Parameter added to $callbackAction to check that we are in a valid callback call
 *
 * @var string
 */
	public $callbackParameter = 'openIDCallback';
/**
 * Controller using the component
 *
 * @var AppController
 */
	public $controller = null;
/**
 * Field mapping (from friendly name to OpenID field)
 *
 * @var array
 */
	public $fieldMapping = array(
		'username' => 'nickname',
		'name' => 'fullname'
	);
/**
 * Mandatory fields to request in the OpenID transaction
 *
 * @var array
 */
	public $requestMandatoryFields = array('username');
/**
 * Optional fields to request in the OpenID transaction
 *
 * @var array
 */
	public $requestOptionalFields = array('name', 'email');
/**
 * Temporary directory used by the php-openid library
 *
 * @var string
 */
	public $tmp = CACHE;
/**
 * Initializes the component for use in the controller
 *
 * @param object $controller A reference to the instantiating controller object
 * @param array $settings Settings for the component
 */
	public function initialize($controller, $settings = array()) {
		parent::initialize($controller, $settings);
		$this->fields = array_merge(array(
			'openid' => 'openid'
		), $this->fields);

		if (!isset($controller->Auth)) {
			$controller->Auth = $this;
		}
		$this->controller = $controller;
	}
/**
 * Main execution method.  Handles redirecting of invalid users, and processing
 * of login form data.
 *
 * @param object $controller A reference to the instantiating controller object
 * @return boolean Success
 */
	public function startup($controller) {
		$result = parent::startup($controller);

		if (empty($this->callbackAction)) {
			$this->callbackAction = $this->loginAction;
		}

		foreach(array('requestOptionalFields', 'requestMandatoryFields') as $parameter) {
			if (!empty($this->$parameter)) {
				foreach($this->$parameter as $key => $value) {
					if (!empty($this->fieldMapping[$value])) {
						$this->{$parameter}[$key] = $this->fieldMapping[$value];
					}
				}
			}
		}

		$url = '';
		if (isset($controller->params['url']['url'])) {
			$url = $controller->params['url']['url'];
		}
		$url = Router::normalize($url);
		$loginAction = Router::normalize($this->loginAction);
		$callbackAction = Router::normalize($this->callbackAction);
		$alias = $this->getModel()->alias;
		$isValid = !empty($controller->data[$alias][$this->fields['openid']]);

        $callbackUrl = Router::url($this->callbackAction, true);
        if (!empty($this->callbackParameter)) {
            $callbackUrl .= (strpos($callbackAction, '?') === false ? '?' : '&') . $this->callbackParameter;
        }

		if ($loginAction == $url && !empty($controller->data) && $isValid && !$result) {
			$this->Session->delete('Message.auth');
			try {
				$this->_openLogin($controller->data[$alias][$this->fields['openid']], $callbackUrl);
			} catch(Exception $e) {
				$result = false;
				$this->Session->setFlash($e->getMessage(), $this->flashElement, array(), 'auth');
			}
		} elseif ($callbackAction == $url && (empty($this->callbackParameter) || array_key_exists($this->callbackParameter, $this->params['url']))) {
			$user = null;
			try {
				$user = $this->_openAuthenticate($callbackUrl);
			} catch(Exception $e) {
				$result = false;
				$this->Session->setFlash($e->getMessage(), $this->flashElement, array(), 'auth');
			}

			if (is_array($user)) {
				if (!empty($this->attachId)) {
					$user['id'] = $this->attachId;
					switch($this->attachId) {
						case 'hash':
							$user['id'] = Security::hash($openid);
							break;
						case 'uuid':
							$user['id'] = String::uuid();
							break;
					}
				}

				$user = array($this->getModel()->alias => $user);
				$this->Session->write($this->sessionKey, $user);
				$this->_loggedIn = true;
				if ($this->autoRedirect) {
					$controller->redirect($this->redirect());
				}
			}
		}
		return $result;
	}
/**
 * Attempts an OpenID login with the given URL / EMAIL
 *
 * @param string $openId OpenID URL / Email
 * @param string $callbackUrl Full URL to callback
 * @throws Exception
 */
	protected function _openLogin($openId, $callbackUrl) {
		if (Validation::email($openId)) {
			App::import('Vendor', 'Auth_Yadis_Email', array('file' => 'Auth'.DS.'Yadis'.DS.'Email.php'));
			if (function_exists('Auth_Yadis_Email_getID')) {
				$openId = Auth_Yadis_Email_getID($openId);
			} else {
				throw new Exception(__('Can\'t convert from an email to an OpenID URL', true));
			}
		}

		$authRequest = $this->_getConsumer()->begin($openId);
		if (!$authRequest) {
			throw new Exception(__('Authentication error; not a valid OpenID', true));
		}
		$sregRequest = Auth_OpenID_SRegRequest::build($this->requestMandatoryFields, $this->requestOptionalFields);
		if ($sregRequest) {
			$authRequest->addExtension($sregRequest);
		}

		$rootUrl = preg_replace('/^(https?:\/\/[^\/]+' . (!empty($this->controller->base) ? preg_quote($this->controller->base) : '') . ').*$/i', '\\1', $callbackUrl);
		if ($authRequest->shouldSendRedirect()) {
			$redirectUrl = $authRequest->redirectURL($rootUrl, $callbackUrl);
			if (Auth_OpenID::isFailure($redirectUrl)) {
				throw new Exception(sprintf(__('Could not redirect to server: %s', true), $redirectUrl->message));
			}
			$this->controller->redirect($redirectUrl);
		} else {
			$id = 'openid';
			$html = $authRequest->htmlMarkup($rootUrl, $callbackUrl);
			if (Auth_OpenID::isFailure($html)) {
				throw new Exception(sprintf(__('Could not redirect to server: %s', true), $html->message));
			}
            echo $html;
			$this->_stop();
		}
	}
/**
 * Authenticate with given OpenID credentials
 *
 * @param string $callbackUrl Full URL to callback
 * @return array Account information
 * @throws Exception
 */
	protected function _openAuthenticate($callbackUrl) {
		$ignore = array('url'=>null);
		if (!empty($this->callbackParameter)) {
			$ignore[$this->callbackParameter] = null;
		}

		$response = $this->_getConsumer()->complete($callbackUrl, array_diff_key(Auth_OpenID::getQuery(), $ignore));
		if ($response->status != Auth_OpenID_SUCCESS) {
			$error = __('Unknown error', true);
			switch($response->status) {
				case Auth_OpenID_CANCEL:
					$error = __('Verification cancelled', true);
					break;
				case Auth_OpenID_FAILURE:
					$error = sprintf(__('OpenID authentication failed: %s', true), $response->message);
					break;
			}echo $error; exit;
			throw new Exception($error);
		}

		$openid = $response->getDisplayIdentifier();
		$sregResp = Auth_OpenID_SRegResponse::fromSuccessResponse($response);
		$contents = $sregResp->contents();

		if (!empty($contents)) {
			$mapping = array_flip($this->fieldMapping);
			foreach($contents as $key => $value) {
				if (empty($mapping[$key])) {
					continue;
				}
				unset($contents[$key]);
				$contents[$mapping[$key]] = $value;
			}
		}
		return (array) $contents;
	}
/**
 * Get the OpenID consumer
 *
 * @return Auth_OpenID_Consumer Consumer
 */
	protected function _getConsumer() {
		return new Auth_OpenID_Consumer(new Auth_OpenID_FileStore($this->tmp));
	}
}
?>

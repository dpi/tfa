<?php

namespace Drupal\tfa\Plugin\Tfa;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Url;
use Drupal\tfa\Plugin\TfaLoginInterface;
use Drupal\tfa\Plugin\TfaSetupInterface;
use Drupal\tfa\TfaBasePlugin;
use Drupal\user\UserDataInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Trusted browser validation class.
 *
 * @Tfa(
 *   id = "tfa_trusted_browser",
 *   label = @Translation("TFA Trusted Browser"),
 *   description = @Translation("TFA Trusted Browser Plugin"),
 *   setupMessages = {
 *    "saved" = @Translation("Browser saved."),
 *    "skipped" = @Translation("Browser not saved."),
 *   }
 * )
 */
class TfaTrustedBrowser extends TfaBasePlugin implements TfaLoginInterface, TfaSetupInterface, ContainerFactoryPluginInterface {

  /**
   * Trust browser.
   *
   * @var bool
   */
  protected $trustBrowser;

  /**
   * Is cookie allowed in subdomains.
   *
   * @var bool
   */
  protected $allowSubdomains;

  /**
   * The cookie name.
   *
   * @var string
   */
  protected $cookieName;

  /**
   * Cookie expiration time.
   *
   * @var string
   */
  protected $expiration;

  /**
   * The current request.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $request;

  /**
   * Constructs a new Tfa plugin object.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin id.
   * @param mixed $plugin_definition
   *   The plugin definition.
   * @param \Drupal\user\UserDataInterface $user_data
   *   User data object to store user specific information.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, UserDataInterface $user_data, ConfigFactoryInterface $config_factory, RequestStack $request_stack) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    $plugin_settings = $config_factory->get('tfa.settings')->get('login_plugin_settings');
    $settings = $plugin_settings['tfa_trusted_browser'] ?? [];
    // Expiration defaults to 30 days.
    $settings = array_replace([
      'cookie_allow_subdomains' => TRUE,
      'cookie_expiration' => 30,
      'cookie_name' => 'tfa-trusted-browser',
    ], $settings);
    $this->allowSubdomains = $settings['cookie_allow_subdomains'];
    $this->expiration = $settings['cookie_expiration'];
    $this->cookieName = $settings['cookie_name'];
    $this->userData = $user_data;
    $this->request = $request_stack->getCurrentRequest();
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('user.data'),
      $container->get('config.factory'),
      $container->get('request_stack')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function loginAllowed() {
    $id = $this->request->cookies->get($this->cookieName);
    if (isset($id) && ($this->trustedBrowser($id) !== FALSE)) {
      // Update browser last used time.
      $result = $this->getUserData('tfa', 'tfa_trusted_browser', $this->uid);
      $result[$id]['last_used'] = \Drupal::time()->getRequestTime();
      $data = [
        'tfa_trusted_browser' => $result,
      ];
      $this->setUserData('tfa', $data, $this->uid);
      return TRUE;
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form, FormStateInterface $form_state) {
    $form['trust_browser'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Remember this browser for @time days?', ['@time' => $this->expiration]),
      '#description' => $this->t('Not recommended if you are on a public or shared computer.'),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array $form, FormStateInterface $form_state) {
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array $form, FormStateInterface &$form_state) {
    $trust_browser = $form_state->getValue('trust_browser');
    if (!empty($trust_browser)) {
      $this->setTrusted($this->generateBrowserId(), $this->getAgent());
    }
  }

  /**
   * The configuration form for this login plugin.
   *
   * @return array
   *   Form array specific for this login plugin.
   */
  public function buildConfigurationForm() {
    $settings_form['cookie_allow_subdomains'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow cookie in subdomains'),
      '#default_value' => $this->allowSubdomains,
      '#description' => $this->t("If set, the cookie will be valid in the same subdomains as core's session cookie, otherwise it is only valid in the exact domain used to log in."),
    ];
    $settings_form['cookie_expiration'] = [
      '#type' => 'number',
      '#title' => $this->t('Cookie expiration'),
      '#default_value' => $this->expiration,
      '#description' => $this->t('Number of days to remember the trusted browser.'),
      '#min' => 1,
      '#max' => 365,
      '#size' => 2,
      '#required' => TRUE,
    ];
    $settings_form['cookie_name'] = [
      '#type' => 'value',
      '#title' => $this->t('Cookie name'),
      '#value' => $this->cookieName,
    ];

    return $settings_form;
  }

  /**
   * Finalize the browser setup.
   *
   * @throws \Exception
   */
  public function finalize() {
    if ($this->trustBrowser) {
      $name = $this->getAgent();
      $this->setTrusted($this->generateBrowserId(), $name);
    }
  }

  /**
   * Generate a random value to identify the browser.
   *
   * @return string
   *   Base64 encoded browser id.
   *
   * @throws \Exception
   */
  protected function generateBrowserId() {
    $id = base64_encode(random_bytes(32));
    return strtr($id, ['+' => '-', '/' => '_', '=' => '']);
  }

  /**
   * Store browser value and issue cookie for user.
   *
   * @param string $id
   *   Trusted browser id.
   * @param string $name
   *   The custom browser name.
   */
  protected function setTrusted($id, $name = '') {
    // Currently broken.
    // Store id for account.
    $records = $this->getUserData('tfa', 'tfa_trusted_browser', $this->configuration['uid']) ?: [];
    $request_time = \Drupal::time()->getRequestTime();

    $records[$id] = [
      'created' => $request_time,
      'ip' => \Drupal::request()->getClientIp(),
      'name' => $name,
    ];
    $this->setUserData('tfa', ['tfa_trusted_browser' => $records], $this->configuration['uid']);

    // Issue cookie with ID.
    $cookie_secure = ini_get('session.cookie_secure');
    $expiration = $request_time + $this->expiration * 86400;
    $domain = $this->allowSubdomains ? ini_get('session.cookie_domain') : '';
    setcookie($this->cookieName, $id, $expiration, base_path(), $domain, !empty($cookie_secure), TRUE);

    // @todo use services defined in module instead this procedural way.
    \Drupal::logger('tfa')->info('Set trusted browser for user UID @uid, browser @name', [
      '@name' => empty($name) ? $this->getAgent() : $name,
      '@uid' => $this->uid,
    ]);
  }

  /**
   * Check if browser id matches user's saved browser.
   *
   * @param string $id
   *   The browser ID.
   *
   * @return bool
   *   TRUE if ID exists otherwise FALSE.
   */
  protected function trustedBrowser($id) {
    // Check if $id has been saved for this user.
    $result = $this->getUserData('tfa', 'tfa_trusted_browser', $this->uid);
    if (isset($result[$id])) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Delete users trusted browser.
   *
   * @param string $id
   *   (optional) Id of the browser to be purged.
   *
   * @return bool
   *   TRUE is id found and purged otherwise FALSE.
   */
  protected function deleteTrusted($id = '') {
    $result = $this->getUserData('tfa', 'tfa_trusted_browser', $this->uid);
    if ($id) {
      if (isset($result[$id])) {
        unset($result[$id]);
        $data = [
          'tfa_trusted_browser' => $result,
        ];
        $this->setUserData('tfa', $data, $this->uid);
        return TRUE;
      }
    }
    else {
      $this->deleteUserData('tfa', 'tfa_trusted_browser', $this->uid);
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Get simplified browser name from user agent.
   *
   * @param string $name
   *   Default browser name.
   *
   * @return string
   *   Simplified browser name.
   */
  protected function getAgent($name = '') {
    $agent = $this->request->server->get('HTTP_USER_AGENT');
    if (isset($agent)) {
      // Match popular user agents.
      if (preg_match("/like\sGecko\)\sChrome\//", $agent)) {
        $name = 'Chrome';
      }
      elseif (strpos($agent, 'Firefox') !== FALSE) {
        $name = 'Firefox';
      }
      elseif (strpos($agent, 'MSIE') !== FALSE) {
        $name = 'Internet Explorer';
      }
      elseif (strpos($agent, 'Safari') !== FALSE) {
        $name = 'Safari';
      }
      else {
        // Otherwise filter agent and truncate to column size.
        $name = substr($agent, 0, 255);
      }
    }
    return $name;
  }

  /* ================================== SETUP ================================== */

  /**
   * {@inheritdoc}
   */
  public function getSetupForm(array $form, FormStateInterface $form_state) {
    $existing = $this->getTrustedBrowsers();
    $form['info'] = [
      '#type' => 'markup',
      '#markup' => '<p>' . $this->t("Trusted browsers are a method for
      simplifying login by avoiding verification code entry for a set amount of
      time, @time days from marking a browser as trusted. After @time days, to
      log in you'll need to enter a verification code with your username and
      password during which you can again mark the browser as trusted.",
      ['@time' => $this->expiration]) . '</p>',
    ];
    // Present option to trust this browser if it's not currently trusted.
    $id = $this->request->cookies->get($this->cookieName);
    if (isset($id) && ($this->trustedBrowser($id) !== FALSE)) {
      $current_trusted = $id;
    }
    else {
      $current_trusted = FALSE;
      $form['trust'] = [
        '#type' => 'checkbox',
        '#title' => $this->t('Trust this browser?'),
        '#default_value' => empty($existing) ? 1 : 0,
      ];
      // Optional field to name this browser.
      $form['name'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Name this browser'),
        '#maxlength' => 255,
        '#description' => $this->t('Optionally, name the browser on your browser (e.g.
        "home firefox" or "office desktop windows"). Your current browser user
        agent is %browser', ['%browser' => $this->request->server->get('HTTP_USER_AGENT')]),
        '#default_value' => $this->getAgent(),
        '#states' => [
          'visible' => [
            ':input[name="trust"]' => ['checked' => TRUE],
          ],
        ],
      ];
    }
    if (!empty($existing)) {
      $form['existing'] = [
        '#type' => 'fieldset',
        '#title' => $this->t('Existing browsers'),
        '#description' => $this->t('Leave checked to keep these browsers in your trusted log in list.'),
        '#tree' => TRUE,
      ];

      foreach ($existing as $browser_id => $browser) {
        $date_formatter = \Drupal::service('date.formatter');
        $vars = [
          '@set' => $date_formatter->format($browser['created']),
        ];

        if (isset($browser['last_used'])) {
          $vars['@time'] = $date_formatter->format($browser['last_used']);
        }

        if ($current_trusted == $browser_id) {
          $name = '<strong>' . $this->t('@name (current browser)', ['@name' => $browser['name']]) . '</strong>';
        }
        else {
          $name = Html::escape($browser['name']);
        }

        if (empty($browser['last_used'])) {
          $message = $this->t('Marked trusted @set', $vars);
        }
        else {
          $message = $this->t('Marked trusted @set, last used for log in @time', $vars);
        }
        $form['existing']['trusted_browser_' . $browser_id] = [
          '#type' => 'checkbox',
          '#title' => $name,
          '#description' => $message,
          '#default_value' => 1,
        ];
      }
    }
    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['save'] = [
      '#type' => 'submit',
      '#button_type' => 'primary',
      '#value' => $this->t('Save'),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateSetupForm(array $form, FormStateInterface $form_state) {
    // Do nothing, no validation required.
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function submitSetupForm(array $form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    if (isset($values['existing'])) {
      $count = 0;
      foreach ($values['existing'] as $element => $value) {
        $id = str_replace('trusted_browser_', '', $element);
        if (!$value) {
          $this->deleteTrusted($id);
          $count++;
        }
      }
      if ($count) {
        \Drupal::logger('tfa')->notice('Removed @num TFA trusted browsers during trusted browser setup', ['@num' => $count]);
      }
    }
    if (!empty($values['trust']) && $values['trust']) {
      $name = '';
      if (!empty($values['name'])) {
        $name = $values['name'];
      }
      elseif (!empty($this->request->server->get('HTTP_USER_AGENT'))) {
        $name = $this->getAgent();
      }
      $this->setTrusted($this->generateBrowserId(), $name);
    }
    return TRUE;
  }

  /**
   * Get list of trusted browsers.
   *
   * @return array
   *   List of current trusted browsers.
   */
  public function getTrustedBrowsers() {
    return $this->getUserData('tfa', 'tfa_trusted_browser', $this->uid) ?: [];
  }

  /**
   * {@inheritdoc}
   */
  public function getOverview(array $params) {
    $trusted_browsers = [];
    foreach ($this->getTrustedBrowsers() as $device) {
      $date_formatter = \Drupal::service('date.formatter');
      $vars = [
        '@set' => $date_formatter->format($device['created']),
        '@browser' => $device['name'],
      ];
      if (empty($device['last_used'])) {
        $message = $this->t('@browser, set @set', $vars);
      }
      else {
        $vars['@time'] = $date_formatter->format($device['last_used']);
        $message = $this->t('@browser, set @set, last used @time', $vars);
      }
      $trusted_browsers[] = $message;
    }
    $output = [
      'heading' => [
        '#type' => 'html_tag',
        '#tag' => 'h3',
        '#value' => $this->t('Trusted browsers'),
      ],
      'description' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('Browsers that will not require a verification code during login.'),
      ],
    ];
    $output['list'] = [
      '#theme' => 'item_list',
      '#items' => $trusted_browsers,
      '#empty' => $this->t('No trusted browsers found.'),
    ];

    $output['link'] = [
      '#theme' => 'links',
      '#links' => [
        'admin' => [
          'title' => $this->t('Configure trusted browsers'),
          'url' => Url::fromRoute('tfa.validation.setup', [
            'user' => $params['account']->id(),
            'method' => $params['plugin_id'],
          ]),
        ],
      ],
    ];

    return $output;
  }

}

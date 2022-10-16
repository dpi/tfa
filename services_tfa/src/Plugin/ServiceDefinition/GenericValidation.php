<?php

namespace Drupal\services_tfa\Plugin\ServiceDefinition;

use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\services\ServiceDefinitionBase;
use Drupal\tfa\TfaPluginManager;
use Drupal\user\UserDataInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * TFA web service.
 *
 * @ServiceDefinition(
 *   id = "tfa_login",
 *   methods = {
 *     "POST"
 *   },
 *   translatable = true,
 *   title = @Translation("TFA Login"),
 *   description = @Translation("Allows user to login through TFA authentication."),
 *   category = @Translation("Security"),
 *   path = "auth/tfa"
 * )
 */
class GenericValidation extends ServiceDefinitionBase implements ContainerFactoryPluginInterface {
  use DependencySerializationTrait;

  /**
   * Validation plugin manager.
   *
   * @var \Drupal\tfa\TfaPluginManager
   */
  protected $tfaPluginManager;

  /**
   * The validation plugin object.
   *
   * @var \Drupal\tfa\Plugin\TfaValidationInterface
   */
  protected $validationPlugin;

  /**
   * User data service.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * TFA Web Services constructor.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param mixed $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\user\UserDataInterface $user_data
   *   User data service.
   * @param \Drupal\tfa\TfaPluginManager $tfa_plugin_manager
   *   Tfa plugin manager.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, UserDataInterface $user_data, TfaPluginManager $tfa_plugin_manager) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    $this->userData = $user_data;
    $this->tfaPluginManager = $tfa_plugin_manager;
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
      $container->get('plugin.manager.tfa')
    );
  }

  /**
   * {@inheritdoc}
   */
  /*
  public function processRoute(Route $route) {
  // @todo Figure out why this results in 403.
  $route->setRequirement('_user_is_logged_in', 'FALSE');
  }
   */

  /**
   * {@inheritdoc}
   */
  public function processRequest(Request $request, RouteMatchInterface $route_match, SerializerInterface $serializer) {
    $uid = $request->get('id');
    $code = $request->get('code');
    $plugin_id = $request->get('plugin_id');

    if ($uid && $code && $plugin_id) {
      $this->validationPlugin = $this->tfaPluginManager->createInstance($plugin_id, ['uid' => $uid]);
      // @todo validateRequest is not part of TfaValidationInterface.
      $valid = $this->validationPlugin->validateRequest($code);
      if ($this->validationPlugin->isAlreadyAccepted()) {
        throw new AccessDeniedHttpException('Invalid code, it was recently used for a login. Please try a new code.');
      }
      elseif (!$valid) {
        throw new AccessDeniedHttpException('Invalid application code. Please try again.');
      }
      else {
        return 1;
      }
    }
    else {
      throw new AccessDeniedHttpException('Required parameters missing.');
    }
  }

}

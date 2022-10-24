<?php

namespace Drupal\tfa;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Plugin\DefaultPluginManager;

/**
 * Tfa plugin manager.
 */
class TfaPluginManager extends DefaultPluginManager {

  /**
   * Constructs TfaPluginManager object.
   *
   * @param \Traversable $namespaces
   *   An object that implements \Traversable which contains the root paths
   *   keyed by the corresponding namespace to look for plugin implementations.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   Cache backend instance to use.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler to invoke the alter hook with.
   */
  public function __construct(\Traversable $namespaces, CacheBackendInterface $cache_backend, ModuleHandlerInterface $module_handler) {
    parent::__construct(
      'Plugin/Tfa',
      $namespaces,
      $module_handler,
      'Drupal\tfa\TfaPluginInterface',
      'Drupal\tfa\Annotation\Tfa'
    );
    $this->alterInfo('tfa_info');
    $this->setCacheBackend($cache_backend, 'tfa_plugins');
  }

  /**
   * Return plugin definitions for all validation plugins.
   *
   * @return array
   *   Array of validation plugin definitions.
   */
  public function getValidationDefinitions() {
    return $this->getClassDefinitions('\Drupal\tfa\Plugin\TfaValidationInterface');
  }

  /**
   * Return plugin definitions for all login plugins.
   *
   * @return array
   *   Array of login plugin definitions.
   */
  public function getLoginDefinitions() {
    return $this->getClassDefinitions('\Drupal\tfa\Plugin\TfaLoginInterface');
  }

  /**
   * Return plugin definitions for all send plugins.
   *
   * @return array
   *   Array of send plugin definitions.
   */
  public function getSendDefinitions() {
    return $this->getClassDefinitions('\Drupal\tfa\Plugin\TfaSendInterface');
  }

  /**
   * Return plugin definitions for all plugins implementing the given class.
   *
   * @param string $class
   *   Name of the class or interface that the plugins must implement.
   *
   * @return array
   *   Array of plugin definitions.
   */
  public function getClassDefinitions(string $class) {
    $all_plugins = $this->getDefinitions();
    $plugins = [];

    foreach ($all_plugins as $key => $plugin) {
      if (is_a($plugin['class'], $class, TRUE)) {
        $plugins[$key] = $plugin;
      }
    }
    return $plugins;
  }

}

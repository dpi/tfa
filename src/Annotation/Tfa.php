<?php

namespace Drupal\tfa\Annotation;

use Drupal\Component\Annotation\Plugin;

/**
 * Defines a TFA annotation object.
 *
 * @Annotation
 */
class Tfa extends Plugin {

  /**
   * The plugin ID.
   *
   * @var string
   */
  public $id;

  /**
   * The human-readable name of the plugin.
   *
   * @var \Drupal\Core\Annotation\Translation
   *
   * @ingroup plugin_translatable
   */
  public $title;

  /**
   * The description of the plugin.
   *
   * @var \Drupal\Core\Annotation\Translation
   *
   * @ingroup plugin_translatable
   */
  public $description;

  /**
   * The helper metadata for setup plugin.
   *
   * @var string[]
   */
  public $helpLinks;

  /**
   * The messages to be displayed during setup steps.
   *
   * @var string[]
   */
  public $setupMessages;

}

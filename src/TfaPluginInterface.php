<?php

namespace Drupal\tfa;

/**
 * Interface for tfa plugins.
 */
interface TfaPluginInterface {

  /**
   * Returns the translated plugin label.
   *
   * @return string
   *   The translated title.
   */
  public function getLabel();

  /**
   * Returns a list of links containing helpful information for plugin use.
   *
   * @return string[]
   *   An array containing help links for e.g., OTP generation.
   */
  public function getHelpLinks();

  /**
   * Returns a list of messages for plugin step.
   *
   * @return string[]
   *   An array containing messages to be used during plugin setup.
   */
  public function getSetupMessages();

}

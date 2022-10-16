<?php

namespace Drupal\tfa\Plugin;

use Drupal\Core\Form\FormStateInterface;

/**
 * Interface TfaLoginInterface.
 *
 * Login plugins interact with the Tfa loginAllowed() process prior to starting
 * a TFA process.
 */
interface TfaLoginInterface {

  /**
   * Get TFA process form from plugin.
   *
   * @param array $form
   *   The configuration form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   *
   * @return array
   *   Form API array.
   */
  public function getForm(array $form, FormStateInterface $form_state);

  /**
   * Validate form.
   *
   * @param array $form
   *   The configuration form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   *
   * @return bool
   *   Whether form passes validation or not
   */
  public function validateForm(array $form, FormStateInterface $form_state);

  /**
   * Whether login is allowed.
   *
   * @return bool
   *   Whether login is allowed.
   */
  public function loginAllowed();

}

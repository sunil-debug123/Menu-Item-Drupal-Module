<?php

namespace Drupal\menu_item_group_role_access;

use Drupal\Core\Access\AccessManagerInterface;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Config\ConfigManagerInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Menu\DefaultMenuLinkTreeManipulators;
use Drupal\Core\Menu\MenuLinkInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\group\Entity\GroupMembership;
use Drupal\group\Entity\GroupRole;
use Drupal\menu_link_content\Entity\MenuLinkContent;
use Drupal\user\Entity\User;

/**
 * Defines the access control handler for the menu item.
 */
class MenuItemRoleAccessLinkTreeManipulator extends DefaultMenuLinkTreeManipulators {

  /**
   * The configuration manager.
   *
   * @var \Drupal\Core\Config\ConfigManagerInterface
   */
  protected $configManager;

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountInterface
   */
  protected $currentUser;

  /**
   * The group membership loader service.
   *
   * @var \Drupal\group\GroupMembershipLoaderInterface
   */
  protected $groupMembershipLoader;

  /**
   * The menu link.
   *
   * @var \Drupal\menu_link_content\MenuLinkContentInterface
   */
  protected $menuLink;

  /**
   * The entity repository.
   *
   * @var \Drupal\Core\Entity\EntityRepository
   */
  protected $entityRepository;

  /**
   * Constructs a \Drupal\Core\Menu\DefaultMenuLinkTreeManipulators object.
   *
   * @param \Drupal\Core\Access\AccessManagerInterface $access_manager
   *   The access manager.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The current user.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigManagerInterface $config_manager
   *   The configuration manager.
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entity_repository
   *   An implementation of the entity repository interface.
   */
  public function __construct(AccessManagerInterface $access_manager,
  AccountInterface $account,
  EntityTypeManagerInterface $entity_type_manager,
  ConfigManagerInterface $config_manager,
  EntityRepositoryInterface $entity_repository,
  ) {
    parent::__construct($access_manager, $account, $entity_type_manager);
    $this->configManager = $config_manager->getConfigFactory();
    $this->entityRepository = $entity_repository;
    $this->currentUser = $account;
  }

  /**
   * Checks access for one menu link instance.
   *
   * This function adds to the checks provided by
   * DefaultMenuLinkTreeManipulators to allow us to check any roles which
   * have been added to a menu item to allow or deny access.
   *
   * @param \Drupal\Core\Menu\MenuLinkInterface $instance
   *   The menu link instance.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   The access result.
   */
  protected function menuLinkCheckAccess(MenuLinkInterface $instance) {
    $access_result = parent::menuLinkCheckAccess($instance);

    // Check if the current user has the 'link to any page' permission.
    if (!$this->account->hasPermission('link to any page')) {
      $metadata = $instance->getMetaData();

      // Check if the menu link is associated with an entity.
      if (isset($metadata['entity_id'])) {
        // Load the entity of the menu item so we can get the roles.
        /** @var \Drupal\menu_link_content\Entity\MenuLinkContent $menu_link_item */
        $menu_link_item = $this->entityTypeManager->getStorage('menu_link_content')->load($metadata['entity_id']);
        // Check if the menu link item is valid and has the required field.
        if (!empty($menu_link_item) && $menu_link_item->hasField('menu_item_group_role_field')) {
          $menu_link_item = $this->getOverridingParent($menu_link_item);
          $allowed_roles = array_column($menu_link_item->get('menu_item_group_role_field')->getValue(), 'value');

          // Check if there are allowed roles for the menu link.
          if (!empty($allowed_roles)) {
            // Set the access result as forbidden by default.
            $access_result = AccessResult::forbidden();

            // Check if the current user is authenticated.
            if ($this->currentUser->isAuthenticated()) {
              /** @var \Drupal\user\Entity\User $user */
              $user = $this->entityTypeManager->getStorage('user')->load($this->currentUser->id());
              // Check if the user has allowed group roles.
              if ($this->userHasGroupRole($user, $allowed_roles)) {
                return AccessResult::allowed();
              }
            }
          }
        }
      }
    }

    return $access_result->cachePerPermissions();
  }

  /**
   * Get the first parent that overrides the childrens' settings.
   *
   * This method gets the parent that has the 'Override children' option
   * enabled. If none was found the input is returned for ease of use. It goes
   * one level up each time and stops at the first match found. This allows for
   * a children to overrule their parent.
   *
   * @param \Drupal\menu_link_content\Entity\MenuLinkContent $menu_link_item
   *   The original menu link item.
   *
   * @return \Drupal\menu_link_content\Entity\MenuLinkContent
   *   The menu link item whose access rules to use.
   */
  protected function getOverridingParent(MenuLinkContent $menu_link_item) {
    // We want the parent overriding permission to overrule the menu-item roles.
    $parent_id = $menu_link_item->getParentId();
    if (!empty($parent_id)) {
      // For now assume loadByUuid() always returns something and not NULL.
      // Make sure we have check parent items enabled.
      $inherit_parent_access = $this->configManager->get('menu_item_group_role_access.config')
        ->get('inherit_parent_access');
      if ($inherit_parent_access) {
        $parent = $this->loadByUuid($parent_id);
        if ($parent) {
          $override_children_value = $this->getOverrideChildrenValue($parent);

          // The parent has declared to inherit its role settings.
          if ($override_children_value) {
            $menu_link_item = $parent;
          }
          else {
            // The parent did not declare to inherit its role settings.
            // Recursively check grandparents if they have set the option.
            $menu_link_item = $this->getOverridingParent($parent);
          }
        }
      }
    }

    return $menu_link_item;
  }

  /**
   * Get the value of the override children option of a menu item.
   *
   * @param \Drupal\menu_link_content\Entity\MenuLinkContent $menu_link_item
   *   A menu link item entity.
   *
   * @return bool
   *   True if option is checked on the parent, false otherwise.
   */
  protected function getOverrideChildrenValue(MenuLinkContent $menu_link_item) {
    $override_children = $menu_link_item
      ->get('menu_item_override_children')
      ->getValue();

    // Cardinality of the field is 1 so get item 0 from values.
    if (isset($override_children[0]['value'])
      && $override_children[0]['value'] == 1) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Get the loaded menu item entity by a combined UUID string.
   *
   * The combined UUID string is the entity bundle followed by a semicolon and
   * then the UUID. For example:
   * - menu_link_content:ab1cd23f-4567-890e-fg12-34h56i789j01
   *
   * @param string $uuid
   *   The combined UUID string.
   *
   * @return \Drupal\menu_link_content\Entity\MenuLinkContent|bool
   *   The menu link, or FALSE if there is no menu item with the given UUID.
   */
  protected function loadByUuid($uuid) {
    $uuid_fragments = explode(':', $uuid);
    // Make sure we have a valid UUID.
    if (strpos($uuid, ':') !== FALSE && count($uuid_fragments) == 2) {
      return $this->entityRepository->loadEntityByUuid($uuid_fragments[0], $uuid_fragments[1]);
    }
    return FALSE;
  }

  /**
   * Check if the user has a specific group role.
   *
   * @param \Drupal\user\Entity\User $user
   *   The user entity.
   * @param string[] $allowed_roles
   *   An array of role names to check if the user has any of them.
   *
   * @return bool
   *   TRUE if the user has the group role, FALSE otherwise.
   */
  public function userHasGroupRole(User $user, array $allowed_roles) {
    // Get the user's group memberships.
    $group_memberships = GroupMembership::loadByUser($user);

    foreach ($group_memberships as $group_membership) {

      // Get the machine names of the user's group roles.
      $user_group_roles = array_map(
        function (GroupRole $group_role) {
            // Assuming the GroupRole class has a method to get the role ID.
            return $group_role->id();
        },
        $group_membership->getRoles()
      );

      // Check if the user has any of the allowed group roles.
      if (!empty(array_intersect($allowed_roles, $user_group_roles))) {
        return TRUE;
      }
    }

    // If no match is found, return FALSE.
    return FALSE;
  }

}

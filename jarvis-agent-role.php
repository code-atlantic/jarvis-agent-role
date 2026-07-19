<?php
/**
 * Plugin Name:       Jarvis Agent Role
 * Plugin URI:        https://github.com/code-atlantic/jarvis-agent-role
 * Description:        Defines a dedicated, version-controlled "Jarvis" role for the AI agent user. Capabilities are the single source of truth below; bump JARVIS_ROLE_VERSION to re-sync after editing them.
 * Version:           1.6.2
 * Author:            Code Atlantic
 * Author URI:        https://code-atlantic.com
 * License:           GPL-2.0-or-later
 * Requires PHP:      7.4
 * Requires at least: 6.4
 * GitHub Plugin URI: code-atlantic/jarvis-agent-role
 * Primary Branch:    main
 *
 * Updates are delivered via Git Updater from the GitHub repo above — install
 * Git Updater on the site and new tagged releases show up as ordinary plugin
 * updates.
 *
 * Deployment: drop this folder into wp-content/plugins/ on each site and activate
 * when provisioning the Jarvis user + application password. The role re-syncs
 * automatically whenever JARVIS_ROLE_VERSION changes — no need to deactivate/reactivate.
 */

namespace CodeAtlantic\Jarvis;

defined( 'ABSPATH' ) || exit;

/**
 * Bump this whenever the capability list changes. The stored role is rebuilt
 * on the next admin load when this value differs from the saved one. This is the
 * mechanism that makes add_role()'s "already exists, do nothing" behavior moot.
 */
const ROLE_VERSION = '1.5.1';

/** Machine name of the role. Keep stable — changing it orphans the old role. */
const ROLE_SLUG = 'jarvis_agent';

/** Display name shown in the WP admin user editor. */
const ROLE_NAME = 'Jarvis (AI Agent)';

/** Option key tracking which ROLE_VERSION is currently materialized in the DB. */
const VERSION_OPTION = 'jarvis_role_synced_version';

/** Login + email for the provisioned agent user. Override via the filters below. */
const USER_LOGIN = 'jarvis';
const USER_EMAIL = 'jarvis@example.com';

/** Display name + nickname set on the agent user at creation. */
const USER_DISPLAY_NAME = 'Jarvis (AI Agent)';

/**
 * Biographical Info (the `description` field). Surfaces publicly on some themes
 * (author archives, comment author links), so it's written to read in-character
 * yet professional. Override per-site via the `jarvis_user_bio` filter.
 */
const USER_BIO = 'Jarvis is the AI agent for Code Atlantic, working alongside the team behind Popup Maker. He handles content updates, site maintenance, and the operational work that keeps wppopupmaker.com running — precisely, and without being asked twice. Every action he takes is logged and scoped to a deliberately limited set of permissions.';

/** User-meta flag marking an account as one we created — gates re-runs and uninstall. */
const USER_FLAG_META = '_jarvis_agent_user';

/**
 * The single source of truth for what Jarvis can do.
 *
 * Philosophy: "Admin-minus". Everything the MCP/REST tooling exercises, but
 * NONE of the caps that allow arbitrary code execution, plugin/theme changes,
 * file editing, core updates, or user management. A leaked credential can mess
 * with content and settings — it cannot execute PHP or escalate accounts.
 *
 * Every cap maps to a value of true. Edit this list, bump ROLE_VERSION, re-copy.
 *
 * @return array<string,bool>
 */
function capabilities(): array {
	$caps = [
		// --- Baseline ---
		'read'                   => true,

		// --- Content: posts & pages (Editor-equivalent) ---
		'edit_posts'             => true,
		'edit_others_posts'      => true,
		'edit_published_posts'   => true,
		'edit_private_posts'     => true,
		'publish_posts'          => true,
		'delete_posts'           => true,
		'delete_others_posts'    => true,
		'delete_published_posts' => true,
		'delete_private_posts'   => true,
		'read_private_posts'     => true,

		'edit_pages'             => true,
		'edit_others_pages'      => true,
		'edit_published_pages'   => true,
		'edit_private_pages'     => true,
		'publish_pages'          => true,
		'delete_pages'           => true,
		'delete_others_pages'    => true,
		'delete_published_pages' => true,
		'delete_private_pages'   => true,
		'read_private_pages'     => true,

		// --- Media (block-MCP upload_media, asset handling) ---
		'upload_files'           => true,

		// --- Comments (block/term tooling) ---
		// Note: manage_categories is intentionally NOT granted. The Block MCP
		// plugin classifies it as a delete-class cap the agent doesn't need, and
		// nothing we use requires it. See the withheld list below.
		'moderate_comments'      => true,
		'edit_comment'           => true,

		// --- Settings: the big one. Most MCP endpoints gate on this. ---
		// This is effectively the line between "Editor" and "near-admin". It is
		// required for the bulk of the wordpress-mcp / mcp-adapters endpoints.
		'manage_options'         => true,

		// Pattern / template-part / global-styles REST endpoints (used by the
		// Block MCP list_patterns / insert_pattern tools) gate on this.
		'edit_theme_options'     => true,

		// --- Custom post type edit/publish caps (popups, EDD downloads, etc.) ---
		// Derived dynamically from every show_in_rest post type, mirroring the
		// Block MCP plugin's own Agent_Provisioner::derive_capabilities(). This
		// auto-covers CPTs with custom capability_types (popup → edit_popups,
		// download → edit_products) AND any future CPT, so there's no hand-list
		// to rot. See derive_cpt_capabilities() below.
		// (merged in after this array literal)

		// --- Easy Digital Downloads (reports/settings — not CPT-derived) ---
		'view_shop_reports'      => true,
		'manage_shop_settings'   => true,

		// --- Popup Maker (theme CPT + management — not edit-primitive-derived) ---
		'manage_popups'          => true,
		'edit_popup_themes'      => true,

		// --- FluentCRM (CRM MCP endpoints) ---
		'fluentcrm_manage_contacts'  => true,
		'fluentcrm_view_contacts'    => true,
		'fluentcrm_read_campaigns'   => true,
		'fluentcrm_manage_campaigns' => true,
		'fluentcrm_manage_lists'     => true,
		'fluentcrm_manage_subscribers' => true,

		// --- FluentBoards (boards MCP endpoints) ---
		'fluent_boards_view'     => true,
		'fluent_boards_admin'    => true,
	];

	// Merge in edit/publish caps for every show_in_rest post type (popups, EDD
	// products, future CPTs). Done dynamically so the list never goes stale.
	$caps = array_merge( $caps, derive_cpt_capabilities() );

	/**
	 * Filter the Jarvis role capabilities for per-site overrides.
	 *
	 * Lets a single site grant or revoke a cap without forking this file —
	 * e.g. drop `manage_options` on a hardened site, or add a custom cap.
	 * Remember to bump ROLE_VERSION (or pass refresh) so the change materializes.
	 *
	 * @param array<string,bool> $caps
	 */
	return (array) apply_filters( 'jarvis_role_capabilities', $caps );
}

/**
 * Derive edit/publish capabilities from every REST-exposed post type.
 *
 * Mirrors the Block MCP plugin's Agent_Provisioner::derive_capabilities(): walk
 * `post`, `page`, and all `show_in_rest` types, and for each pull the mapped
 * edit/publish primitive cap names off its capability object. A CPT with a
 * custom capability_type contributes its own caps automatically — `popup`
 * yields edit_popups/etc., `download` (capability_type => product) yields
 * edit_products/etc. — so this stays correct as CPTs come and go.
 *
 * Deliberately omits delete-class primitives: the agent edits and publishes but
 * does not hard-delete arbitrary content (consistent with the withheld list).
 *
 * @return array<string,bool>
 */
function derive_cpt_capabilities(): array {
	$caps = [];

	$types = [ 'post', 'page' ];
	if ( function_exists( 'get_post_types' ) ) {
		$types = array_unique(
			array_merge( $types, array_values( get_post_types( [ 'show_in_rest' => true ], 'names' ) ) )
		);
	}

	$primitives = [ 'edit_posts', 'edit_others_posts', 'edit_published_posts', 'publish_posts' ];

	// WordPress sentinel caps that must never be granted to a role. A read-only
	// CPT maps its edit primitives to `do_not_allow` (e.g. the Jarvis activity-log
	// CPT jp_act_log_event); `exist` is the internal "post exists" pseudo-cap.
	// Granting `do_not_allow` poisons map_meta_cap() for existing objects — every
	// edit_post check against a real post then fails "Required capability:
	// edit_post" even though the true edit caps are present.
	$sentinels = [ 'do_not_allow', 'exist' ];

	foreach ( $types as $type ) {
		$object = get_post_type_object( $type );
		if ( ! $object || ! isset( $object->cap ) ) {
			continue;
		}
		foreach ( $primitives as $primitive ) {
			if ( ! isset( $object->cap->$primitive ) ) {
				continue;
			}
			$mapped = $object->cap->$primitive;
			if ( in_array( $mapped, $sentinels, true ) ) {
				continue;
			}
			$caps[ $mapped ] = true;
		}
	}

	return $caps;
}

/**
 * Capabilities deliberately WITHHELD — documented so the exclusion is intentional,
 * not an oversight. Do not add these without a deliberate decision.
 *
 * install_plugins, activate_plugins, edit_plugins, delete_plugins,
 * install_themes, edit_themes, switch_themes, delete_themes,
 * edit_files, edit_themes, update_core, update_plugins, update_themes,
 * create_users, edit_users, delete_users, promote_users, list_users,
 * unfiltered_html, export, import.
 */

/**
 * Create or re-sync the role when ROLE_VERSION changes.
 *
 * add_role() is a no-op if the role already exists, so we remove and re-add to
 * guarantee the cap list matches the array above. Gated on a version check so
 * this runs once per change, not on every request.
 */
function maybe_sync_role(): void {
	if ( get_option( VERSION_OPTION ) !== ROLE_VERSION ) {
		sync_role();
		return;
	}
	// Version unchanged: still re-assert CPT-derived caps. Activation can run
	// before EDD/Popup Maker register their CPTs, so the initial sync may miss
	// them; admin_init runs after CPT registration, so catch any stragglers here
	// without a full rebuild. Mirrors the Block MCP provisioner's re-assert loop.
	reassert_cpt_capabilities();
}

/**
 * Grant any CPT-derived capability the role is currently missing. Cheap no-op
 * once everything's present; only writes when a new cap actually needs adding.
 */
function reassert_cpt_capabilities(): void {
	$role = get_role( ROLE_SLUG );
	if ( ! $role ) {
		return;
	}
	foreach ( derive_cpt_capabilities() as $cap => $granted ) {
		if ( $granted && ! $role->has_cap( $cap ) ) {
			$role->add_cap( $cap );
		}
	}
}

/**
 * Force a rebuild of the role from the capability array. Idempotent.
 */
function sync_role(): void {
	remove_role( ROLE_SLUG );
	add_role( ROLE_SLUG, ROLE_NAME, capabilities() );
	update_option( VERSION_OPTION, ROLE_VERSION );
}

/**
 * Ensure the Jarvis agent user exists and carries the role. Idempotent.
 *
 * Resolution:
 *  - A user already flagged as ours (USER_FLAG_META) → ensure the role is set,
 *    return its ID. Re-runs are no-ops.
 *  - A user with the target login/email exists but is NOT flagged → it belongs
 *    to a real person. We do NOT adopt it, do NOT add the role, and return a
 *    WP_Error. Granting Admin-minus to someone's real account silently would be
 *    a serious footgun.
 *  - No such user → create one on the role with a cryptographically random
 *    password (auth is via application password, so the password is never used
 *    interactively), flag it, and return the new ID.
 *
 * Login and email are filterable so a site can vary them without forking.
 *
 * @return int|\WP_Error Agent user ID, or WP_Error when a non-agent account
 *                       already owns the login/email.
 */
/** The agent's bio (Biographical Info), filterable per-site. */
function bio(): string {
	return (string) apply_filters( 'jarvis_user_bio', USER_BIO );
}

function ensure_user() {
	$login = (string) apply_filters( 'jarvis_user_login', USER_LOGIN );
	$email = (string) apply_filters( 'jarvis_user_email', USER_EMAIL );

	// Already provisioned by us? Re-assert role and return.
	$existing = get_users(
		[
			'meta_key'   => USER_FLAG_META,
			'meta_value' => '1',
			'number'     => 1,
			'fields'     => 'ID',
		]
	);
	if ( ! empty( $existing ) ) {
		$user = get_user_by( 'id', (int) $existing[0] );
		if ( $user && ! in_array( ROLE_SLUG, (array) $user->roles, true ) ) {
			$user->add_role( ROLE_SLUG );
		}
		// Re-assert identity on existing agent accounts so display name / nickname
		// / bio stay in sync if they were created before these were set.
		if ( $user && (
			$user->display_name !== USER_DISPLAY_NAME
			|| get_user_meta( $user->ID, 'nickname', true ) !== USER_DISPLAY_NAME
			|| $user->description !== bio()
		) ) {
			wp_update_user(
				[
					'ID'           => $user->ID,
					'display_name' => USER_DISPLAY_NAME,
					'nickname'     => USER_DISPLAY_NAME,
					'description'  => bio(),
				]
			);
		}
		return (int) $existing[0];
	}

	$by_login = get_user_by( 'login', $login );
	$by_email = get_user_by( 'email', $email );

	// Adopt a manually-created agent account ONLY when BOTH the login and the
	// email match the canonical agent identity and resolve to the same user.
	// That's unambiguously the account we'd have created ourselves (e.g. one made
	// earlier via `wp user create`), so claim it: flag it, set the role + identity.
	if ( $by_login && $by_email && (int) $by_login->ID === (int) $by_email->ID ) {
		$user = $by_login;
		if ( ! in_array( ROLE_SLUG, (array) $user->roles, true ) ) {
			$user->add_role( ROLE_SLUG );
		}
		wp_update_user(
			[
				'ID'           => $user->ID,
				'display_name' => USER_DISPLAY_NAME,
				'nickname'     => USER_DISPLAY_NAME,
				'description'  => bio(),
			]
		);
		update_user_meta( $user->ID, USER_FLAG_META, '1' );
		return (int) $user->ID;
	}

	// Login OR email collides with a DIFFERENT account — refuse to adopt it. This
	// is the footgun guard: never bolt the agent role onto a real person's user.
	if ( $by_login || $by_email ) {
		return new \WP_Error(
			'jarvis_user_conflict',
			sprintf(
				'A user already exists for "%s" or "%s" that is not the canonical agent (login and email do not both match one account). Not adopting it. Flag it manually (user meta %s = 1) or change jarvis_user_login/jarvis_user_email.',
				$login,
				$email,
				USER_FLAG_META
			)
		);
	}

	// Create fresh, on the role, with an unguessable password.
	$user_id = wp_insert_user(
		[
			'user_login'   => $login,
			'user_email'   => $email,
			'user_pass'    => wp_generate_password( 32, true, true ),
			'display_name' => USER_DISPLAY_NAME,
			'nickname'     => USER_DISPLAY_NAME,
			'description'  => bio(),
			'role'         => ROLE_SLUG,
		]
	);

	if ( is_wp_error( $user_id ) ) {
		return $user_id;
	}

	update_user_meta( $user_id, USER_FLAG_META, '1' );

	return (int) $user_id;
}

/**
 * Remove the role on deactivation. Users assigned to it fall back to no role —
 * provision a replacement role before deactivating on a live site.
 *
 * The agent USER is intentionally left intact on deactivation — pulling an
 * account (and its application passwords) out from under a live integration on a
 * simple toggle is too destructive. Removal happens only on uninstall.
 */
function on_deactivate(): void {
	remove_role( ROLE_SLUG );
	delete_option( VERSION_OPTION );
}

// Minimal audit trail for actions taken by the Jarvis user.
require_once __DIR__ . '/includes/audit-log.php';

// Optional read-only SQL ability (jarvis-agent-only, off unless JARVIS_ENABLE_SQL).
require_once __DIR__ . '/includes/sql-ability.php';

/**
 * Activation: register the role, then ensure the agent user exists on it.
 * Order matters — the role must exist before it can be assigned to the user.
 */
function activate(): void {
	sync_role();
	ensure_user();
}

register_activation_hook( __FILE__, __NAMESPACE__ . '\\activate' );
register_deactivation_hook( __FILE__, __NAMESPACE__ . '\\on_deactivate' );
add_action( 'admin_init', __NAMESPACE__ . '\\maybe_sync_role' );

/**
 * Does this avatar request resolve to the Jarvis agent user?
 *
 * Avatar filters receive a mixed identifier (user ID, email, WP_User, WP_Post,
 * WP_Comment). Resolve it to an email and match against the agent address, with
 * the user-flag meta as a fallback so a filtered/overridden email still matches.
 *
 * @param mixed $id_or_email
 */
function is_jarvis_avatar_target( $id_or_email ): bool {
	$email = '';
	$user  = null;

	if ( is_numeric( $id_or_email ) ) {
		$user = get_user_by( 'id', (int) $id_or_email );
	} elseif ( is_string( $id_or_email ) ) {
		$email = $id_or_email;
	} elseif ( $id_or_email instanceof \WP_User ) {
		$user = $id_or_email;
	} elseif ( $id_or_email instanceof \WP_Post ) {
		$user = get_user_by( 'id', (int) $id_or_email->post_author );
	} elseif ( $id_or_email instanceof \WP_Comment ) {
		if ( ! empty( $id_or_email->user_id ) ) {
			$user = get_user_by( 'id', (int) $id_or_email->user_id );
		} else {
			$email = (string) $id_or_email->comment_author_email;
		}
	}

	if ( $user ) {
		if ( get_user_meta( $user->ID, USER_FLAG_META, true ) ) {
			return true;
		}
		$email = $user->user_email;
	}

	$target = (string) apply_filters( 'jarvis_user_email', USER_EMAIL );
	return '' !== $email && strtolower( $email ) === strtolower( $target );
}

/** URL to the bundled avatar image. */
function avatar_url(): string {
	return plugins_url( 'assets/jarvis-avatar.png', __FILE__ );
}

/**
 * Serve the bundled local avatar for the Jarvis user, bypassing Gravatar.
 * Covers get_avatar(), get_avatar_url(), and the block-editor author chip — they
 * all flow through get_avatar_data().
 */
add_filter(
	'get_avatar_data',
	function ( $args, $id_or_email ) {
		if ( is_jarvis_avatar_target( $id_or_email ) ) {
			$args['url']          = avatar_url();
			$args['found_avatar'] = true;
		}
		return $args;
	},
	10,
	2
);

/**
 * WP-CLI: `wp jarvis sync` to force a re-sync without the admin-load trigger.
 * Handy on headless deploys where no admin page is hit.
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command(
		'jarvis sync',
		function () {
			sync_role();
			\WP_CLI::success( sprintf( 'Jarvis role synced to version %s (%d caps).', ROLE_VERSION, count( capabilities() ) ) );
		}
	);

	\WP_CLI::add_command(
		'jarvis user',
		function () {
			$result = ensure_user();
			if ( is_wp_error( $result ) ) {
				\WP_CLI::error( $result->get_error_message() );
			}
			$user = get_user_by( 'id', $result );
			\WP_CLI::success( sprintf( 'Jarvis user ready: %s (ID %d, %s).', $user->user_login, $user->ID, $user->user_email ) );
			\WP_CLI::log( 'Generate an app password:  wp user application-password create ' . $user->user_login . ' "jarvis-mcp" --porcelain' );
		}
	);
}

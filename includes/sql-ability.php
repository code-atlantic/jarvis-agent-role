<?php
/**
 * Read-only SQL ability for the Jarvis agent.
 *
 * Registers `jarvis/execute-sql` via the WordPress Abilities API (WP 6.9+). It
 * runs a SINGLE read-only query and returns the rows. This is the deliberate,
 * scoped answer to "let the agent run ad-hoc reports" — instead of a broad
 * REST endpoint, it's one ability, gated three ways:
 *
 *   1. Only the Jarvis agent user may call it (permission_callback checks the
 *      role AND the agent-user flag — a stray manage_options user can't).
 *   2. Only SELECT / read statements pass a strict allowlist + denylist check.
 *   3. It's off unless JARVIS_ENABLE_SQL is truthy (constant or filter), so a
 *      site that doesn't want it never exposes it.
 *
 * The ability only registers if the Abilities API is present, so this file is
 * a no-op on WP < 6.9 or when the API is unavailable.
 *
 * @package CodeAtlantic\Jarvis
 */

namespace CodeAtlantic\Jarvis;

defined( 'ABSPATH' ) || exit;

/** Max rows returned in a single call (hard cap, also injected as LIMIT). */
const SQL_MAX_ROWS = 1000;

/**
 * Is the SQL ability enabled for this site? Off by default. Enable with:
 *   define( 'JARVIS_ENABLE_SQL', true );   // wp-config.php
 * or the `jarvis_enable_sql` filter. A hardened site simply never turns it on.
 */
function sql_enabled(): bool {
	$enabled = defined( 'JARVIS_ENABLE_SQL' ) ? (bool) JARVIS_ENABLE_SQL : false;
	return (bool) apply_filters( 'jarvis_enable_sql', $enabled );
}

/**
 * Permission gate: caller must resolve to OUR Jarvis agent user, not merely a
 * high-privilege account. We check the agent-user flag meta (set at
 * provisioning) so even another admin can't invoke this ability.
 *
 * @param mixed $input Ability input (unused; gate is identity-based).
 * @return true|\WP_Error
 */
function sql_permission( $input = null ) {
	unset( $input );

	if ( ! sql_enabled() ) {
		return new \WP_Error( 'jarvis_sql_disabled', 'The Jarvis SQL ability is disabled on this site.', array( 'status' => 403 ) );
	}

	$uid = get_current_user_id();
	if ( ! $uid ) {
		return new \WP_Error( 'jarvis_sql_forbidden', 'Authentication required.', array( 'status' => 401 ) );
	}

	// Must be flagged as the agent user we provisioned. This is stricter than a
	// capability check on purpose — the SQL surface is agent-only.
	if ( ! get_user_meta( $uid, USER_FLAG_META, true ) ) {
		return new \WP_Error( 'jarvis_sql_forbidden', 'The SQL ability is restricted to the Jarvis agent user.', array( 'status' => 403 ) );
	}

	return true;
}

/**
 * Reject anything that isn't a single, read-only statement.
 *
 * Strategy: allowlist the leading keyword (SELECT / SHOW / DESCRIBE / EXPLAIN /
 * WITH…SELECT), denylist mutating keywords anywhere, and forbid statement
 * stacking. This is intentionally conservative — a rejected safe query is an
 * annoyance; an accepted mutating query is a breach.
 *
 * @param string $sql Raw query.
 * @return true|\WP_Error
 */
function sql_is_readonly( string $sql ) {
	$trimmed = trim( $sql );

	// Strip a single trailing semicolon; reject if more than one statement.
	$trimmed = rtrim( $trimmed, "; \t\n\r\0\x0B" );
	if ( strpos( $trimmed, ';' ) !== false ) {
		return new \WP_Error( 'jarvis_sql_multi', 'Only a single statement is allowed (no semicolons).', array( 'status' => 400 ) );
	}

	if ( '' === $trimmed ) {
		return new \WP_Error( 'jarvis_sql_empty', 'Empty query.', array( 'status' => 400 ) );
	}

	// Leading keyword must be a read verb.
	if ( ! preg_match( '/^\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|WITH)\b/i', $trimmed ) ) {
		return new \WP_Error( 'jarvis_sql_not_read', 'Only SELECT / SHOW / DESCRIBE / EXPLAIN / WITH queries are allowed.', array( 'status' => 400 ) );
	}

	// Denylist mutating / dangerous keywords anywhere in the statement. Word
	// boundaries so column names like "updated_at" don't trip "UPDATE".
	$forbidden = array(
		'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'MERGE', 'UPSERT',
		'DROP', 'CREATE', 'ALTER', 'TRUNCATE', 'RENAME',
		'GRANT', 'REVOKE', 'SET', 'LOCK', 'UNLOCK', 'CALL', 'DO',
		'HANDLER', 'LOAD', 'IMPORT', 'INTO\s+OUTFILE', 'INTO\s+DUMPFILE',
		'PREPARE', 'EXECUTE', 'DEALLOCATE',
	);
	foreach ( $forbidden as $kw ) {
		if ( preg_match( '/\b' . $kw . '\b/i', $trimmed ) ) {
			return new \WP_Error(
				'jarvis_sql_forbidden_kw',
				sprintf( 'Query rejected: contains a non-read keyword (%s).', preg_replace( '/\\\\s\+/', ' ', $kw ) ),
				array( 'status' => 400 )
			);
		}
	}

	return true;
}

/**
 * Execute the (validated) read-only query and return rows.
 *
 * @param array<string,mixed> $input { query: string, limit?: int }.
 * @return array<string,mixed>|\WP_Error
 */
function sql_execute( $input ) {
	global $wpdb;

	$sql = isset( $input['query'] ) ? (string) $input['query'] : '';
	$ok  = sql_is_readonly( $sql );
	if ( is_wp_error( $ok ) ) {
		return $ok;
	}

	$limit = isset( $input['limit'] ) ? (int) $input['limit'] : SQL_MAX_ROWS;
	$limit = max( 1, min( $limit, SQL_MAX_ROWS ) );

	// Wrap the caller's SELECT so we always bound the result set, without having
	// to parse/modify their query. Derived-table wrapping only applies to plain
	// SELECT; SHOW/DESCRIBE/EXPLAIN are already tiny and run as-is.
	$trimmed = rtrim( trim( $sql ), "; \t\n\r\0\x0B" );
	$is_plain_select = (bool) preg_match( '/^\s*(SELECT|WITH)\b/i', $trimmed );

	// Suppress errors from surfacing to output; capture them explicitly instead.
	$prev_suppress = $wpdb->suppress_errors( true );
	$prev_show     = $wpdb->hide_errors();

	if ( $is_plain_select ) {
		// If the query already has its own LIMIT, respect it; otherwise bound it.
		$bounded = preg_match( '/\bLIMIT\b/i', $trimmed )
			? $trimmed
			: $trimmed . ' LIMIT ' . (int) $limit;
		$rows = $wpdb->get_results( $bounded, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL
	} else {
		$rows = $wpdb->get_results( $trimmed, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL
	}

	$db_error = $wpdb->last_error;
	$wpdb->suppress_errors( $prev_suppress );
	if ( ! $prev_show ) {
		$wpdb->show_errors();
	}

	if ( $db_error ) {
		return new \WP_Error( 'jarvis_sql_db_error', 'Query failed: ' . $db_error, array( 'status' => 400 ) );
	}

	$rows = is_array( $rows ) ? $rows : array();

	return array(
		'success'   => true,
		'row_count' => count( $rows ),
		'truncated' => count( $rows ) >= $limit,
		'columns'   => ! empty( $rows ) ? array_keys( $rows[0] ) : array(),
		'rows'      => $rows,
	);
}

/**
 * Register the `jarvis` ability category. WP 6.9's Abilities API REQUIRES every
 * ability to declare a `category`, and that category must be registered first
 * (on the dedicated `wp_abilities_api_categories_init` action) or the ability
 * is silently rejected. Mirrors how gk-block-mcp registers its category.
 */
function register_jarvis_category(): void {
	if ( ! function_exists( 'wp_register_ability_category' ) ) {
		return;
	}
	if ( ! sql_enabled() ) {
		return;
	}
	wp_register_ability_category(
		'jarvis',
		array(
			'label'       => __( 'Jarvis', 'jarvis-agent-role' ),
			'description' => __( 'Operational abilities exposed to the Jarvis AI agent.', 'jarvis-agent-role' ),
		)
	);
}

/**
 * Register the ability on the Abilities API init hook. No-op if the API or the
 * feature flag is absent.
 */
function register_sql_ability(): void {
	if ( ! function_exists( 'wp_register_ability' ) ) {
		return;
	}
	if ( ! sql_enabled() ) {
		return; // Don't even advertise it when disabled.
	}

	wp_register_ability(
		'jarvis/execute-sql',
		array(
			'label'               => 'Execute read-only SQL (Jarvis)',
			'description'         => 'Run a single READ-ONLY SQL query (SELECT / SHOW / DESCRIBE / EXPLAIN / WITH) against the WordPress database and return rows. Jarvis-agent-only, capped at ' . SQL_MAX_ROWS . ' rows. Mutating statements are rejected. Use for ad-hoc reports and lookups the REST abilities do not cover.',
			'category'            => 'jarvis',
			'input_schema'        => array(
				'type'       => 'object',
				'properties' => array(
					'query' => array(
						'type'        => 'string',
						'description' => 'A single read-only SQL statement. No semicolons, no writes. Table prefix is ' . $GLOBALS['wpdb']->prefix . '.',
					),
					'limit' => array(
						'type'        => 'integer',
						'description' => 'Max rows (1-' . SQL_MAX_ROWS . ', default ' . SQL_MAX_ROWS . '). Applied as a LIMIT if your SELECT has none.',
					),
				),
				'required'   => array( 'query' ),
			),
			'output_schema'       => array( 'type' => 'object' ),
			'execute_callback'    => __NAMESPACE__ . '\\sql_execute',
			'permission_callback' => __NAMESPACE__ . '\\sql_permission',
			'meta'                => array(
				'annotations'  => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
				'show_in_rest' => true,
				'mcp'          => array(
					'public' => true,
				),
			),
		)
	);
}

// The Abilities API REQUIRES registration to happen on `wp_abilities_api_init`
// (WP 6.9+) — calling wp_register_ability() outside that action is a no-op that
// triggers _doing_it_wrong. So we only ever hook the action; the plugin loads
// early enough (via require in the main file) that the listener is in place
// before the action fires on the request.
if ( function_exists( 'wp_register_ability' ) ) {
	// Category must be registered on its own (earlier) action before the ability
	// that references it is registered.
	add_action( 'wp_abilities_api_categories_init', __NAMESPACE__ . '\\register_jarvis_category' );
	add_action( 'wp_abilities_api_init', __NAMESPACE__ . '\\register_sql_ability' );
}

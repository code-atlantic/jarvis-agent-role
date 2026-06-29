<?php
/**
 * Audit log for the Jarvis agent user.
 *
 * Primary capture is at the **Abilities API layer**: the WordPress Abilities API
 * fires `wp_before_execute_ability` / `wp_after_execute_ability` around every
 * ability execution, so hooking those two actions logs every MCP/agent tool call
 * — ours, the core mcp-adapter's, FluentBoards/CRM adapters, and any custom tool
 * added later — with tool name, full input, and result. No per-event guessing, no
 * patching core or vendor files.
 *
 * Auth events (cookie login, application-password) don't run through an ability,
 * so they're captured separately.
 *
 * Logging only fires for users on the `jarvis_agent` role, so human admins and
 * non-agent API clients generate nothing.
 *
 * Storage: JSON-lines file, one event per line. Defaults ABOVE the web root when
 * that location is writable (so the trail isn't web-reachable), else wp-content.
 * Override with the JARVIS_AUDIT_LOG_FILE constant.
 *
 * @package CodeAtlantic\Jarvis
 */

namespace CodeAtlantic\Jarvis\Audit;

use const CodeAtlantic\Jarvis\ROLE_SLUG;

defined( 'ABSPATH' ) || exit;

/** Truncate the log once it exceeds this size (bytes). Keeps growth bounded. */
const MAX_LOG_BYTES = 10485760; // 10 MB.

/**
 * Input/result keys whose VALUES are redacted even in this internal log.
 * Logging a freshly-minted password or app-password plaintext would be a
 * self-inflicted wound regardless of who can read the file. Names matched
 * case-insensitively, substring. Everything else is logged in full.
 */
const REDACT_KEYS = [ 'password', 'pwd', 'secret', 'token', 'app_password', 'application_password', 'private_key', 'api_key' ];

/**
 * Absolute path to the audit log file.
 *
 * Resolution order:
 *   1. JARVIS_AUDIT_LOG_FILE constant, if defined.
 *   2. A `jarvis-audit/` dir one level above WP_CONTENT_DIR (typically above the
 *      web root) when that parent is writable — keeps the trail non-web-reachable.
 *   3. Fallback: inside WP_CONTENT_DIR.
 */
function log_file(): string {
	if ( defined( 'JARVIS_AUDIT_LOG_FILE' ) ) {
		return JARVIS_AUDIT_LOG_FILE;
	}

	$above = dirname( WP_CONTENT_DIR ) . '/jarvis-audit';
	if ( is_dir( $above ) || @mkdir( $above, 0750, true ) || is_writable( dirname( WP_CONTENT_DIR ) ) ) {
		if ( is_dir( $above ) && is_writable( $above ) ) {
			return $above . '/jarvis-audit.log';
		}
	}

	return WP_CONTENT_DIR . '/jarvis-audit.log';
}

/**
 * Is the current actor a Jarvis agent user? Logging is a no-op for everyone else.
 *
 * @param \WP_User|null $user Optional explicit user (for hooks where the current
 *                            user isn't set yet, e.g. auth events).
 */
function actor_is_jarvis( $user = null ): bool {
	$user = $user ?: wp_get_current_user();
	return $user && $user->exists() && in_array( ROLE_SLUG, (array) $user->roles, true );
}

/**
 * Recursively redact sensitive values by key name. Preserves structure so the
 * shape of the call is still auditable; just blanks the dangerous leaves.
 *
 * @param mixed $data
 * @return mixed
 */
function redact( $data ) {
	if ( ! is_array( $data ) ) {
		return $data;
	}
	$out = [];
	foreach ( $data as $key => $value ) {
		$lower = is_string( $key ) ? strtolower( $key ) : '';
		$hit   = false;
		foreach ( REDACT_KEYS as $needle ) {
			if ( '' !== $lower && false !== strpos( $lower, $needle ) ) {
				$hit = true;
				break;
			}
		}
		$out[ $key ] = $hit ? '«redacted»' : redact( $value );
	}
	return $out;
}

/**
 * Append one event to the audit log for the Jarvis actor.
 *
 * @param string              $action  Short verb, e.g. 'ability', 'auth.login'.
 * @param array<string,mixed> $context Structured detail.
 * @param \WP_User|null       $user    Explicit user when current-user isn't ready.
 */
function record( string $action, array $context = [], $user = null ): void {
	if ( ! actor_is_jarvis( $user ) ) {
		return;
	}

	$user = $user ?: wp_get_current_user();

	$entry = [
		'time'    => gmdate( 'c' ), // ISO-8601 UTC; unambiguous across sites.
		'user'    => $user->user_login,
		'user_id' => $user->ID,
		'action'  => $action,
		'ip'      => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
		'context' => $context,
	];

	write_line( wp_json_encode( $entry ) );
}

/**
 * Append a raw line to the log, rotating first if oversized. Failures are
 * swallowed — audit logging must never break the request it's observing.
 */
function write_line( string $line ): void {
	$file = log_file();

	if ( file_exists( $file ) && filesize( $file ) > MAX_LOG_BYTES ) {
		@rename( $file, $file . '.1' );
	}

	// LOCK_EX so concurrent writes don't interleave.
	@file_put_contents( $file, $line . "\n", FILE_APPEND | LOCK_EX );
}

/**
 * Trim a value for logging so a giant blob (e.g. full block HTML) doesn't bloat
 * the line. Internal log, so the cap is generous. Arrays are redacted+returned
 * as-is; long strings are truncated with a marker.
 *
 * @param mixed $value
 * @return mixed
 */
function clip( $value ) {
	if ( is_string( $value ) && strlen( $value ) > 20000 ) {
		return substr( $value, 0, 20000 ) . '…[' . strlen( $value ) . ' bytes]';
	}
	return $value;
}

/* -------------------------------------------------------------------------
 * Primary capture: every ability execution.
 *
 * `wp_before_execute_ability` ( $name, $input )
 * `wp_after_execute_ability`  ( $name, $input, $result )
 *
 * We log on *after* so we can record the outcome (ok/error) in one line. Only
 * the INPUT is recorded — the call's intent and arguments are the audit signal.
 * Result bodies are deliberately NOT logged (a read tool's payload is noise; for
 * write/delete/update tools the input args already capture what changed). On
 * failure we keep the WP_Error code+message, since "it failed, and why" is signal.
 * Input is redacted for credential keys and clipped for size.
 * ---------------------------------------------------------------------- */
add_action(
	'wp_after_execute_ability',
	function ( $name, $input, $result ) {
		if ( ! actor_is_jarvis() ) {
			return;
		}

		$entry = [
			'tool'   => $name,
			'input'  => redact( is_array( $input ) ? array_map( __NAMESPACE__ . '\\clip', $input ) : $input ),
			'status' => is_wp_error( $result ) ? 'error' : 'ok',
		];

		if ( is_wp_error( $result ) ) {
			$entry['error'] = [
				'code'    => $result->get_error_code(),
				'message' => $result->get_error_message(),
			];
		}

		record( 'ability', $entry );
	},
	10,
	3
);

/* -------------------------------------------------------------------------
 * Auth events — these don't flow through an ability, so capture directly.
 * ---------------------------------------------------------------------- */

/**
 * Cookie login for the Jarvis user.
 */
add_action(
	'wp_login',
	function ( $user_login, $user ) {
		record( 'auth.login', [ 'method' => 'cookie' ], $user );
	},
	10,
	2
);

/**
 * Application-password REST authentication — the agent's primary connection path.
 */
add_action(
	'application_password_did_authenticate',
	function ( $user, $item ) {
		record(
			'auth.app_password',
			[ 'app' => isset( $item['name'] ) ? $item['name'] : '' ],
			$user
		);
	},
	10,
	2
);

/* -------------------------------------------------------------------------
 * WP-CLI: `wp jarvis audit [--lines=N]` to tail the trail.
 * ---------------------------------------------------------------------- */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command(
		'jarvis audit',
		function ( $args, $assoc_args ) {
			$file = log_file();
			if ( ! file_exists( $file ) ) {
				\WP_CLI::warning( 'No audit log yet at ' . $file );
				return;
			}
			$lines = isset( $assoc_args['lines'] ) ? max( 1, (int) $assoc_args['lines'] ) : 20;
			$all   = file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
			foreach ( array_slice( $all, -$lines ) as $line ) {
				\WP_CLI::line( $line );
			}
			\WP_CLI::log( "\n" . $file );
		}
	);
}

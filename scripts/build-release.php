<?php
/**
 * Build the deterministic Checkout Firewall Free release ZIP.
 *
 * Usage: php scripts/build-release.php [output.zip]
 */

declare(strict_types=1);

const CWF_PUBLIC_MIRROR_MTIME = 315532800;

$root   = dirname(__DIR__);
$output = $argv[1] ?? $root . '/dist/checkout-firewall-1.0.0.zip';

if (! class_exists(ZipArchive::class)) {
	fwrite(STDERR, "The PHP Zip extension is required.\n");
	exit(1);
}

$runtime_files = array(
	'THIRD-PARTY-NOTICES.txt',
	'checkout-firewall.php',
	'readme.txt',
	'uninstall.php',
);
$runtime_directories = array(
	'assets',
	'config',
	'languages',
	'src',
	'vendor',
);
$paths = array();

foreach ($runtime_files as $relative) {
	if (! is_file($root . '/' . $relative)) {
		fwrite(STDERR, "Missing runtime file: {$relative}\n");
		exit(1);
	}
	$paths[] = $relative;
}

foreach ($runtime_directories as $directory) {
	$absolute = $root . '/' . $directory;
	if (! is_dir($absolute)) {
		fwrite(STDERR, "Missing runtime directory: {$directory}\n");
		exit(1);
	}
	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($absolute, FilesystemIterator::SKIP_DOTS)
	);
	foreach ($iterator as $file) {
		if ($file->isFile()) {
			$paths[] = substr($file->getPathname(), strlen($root) + 1);
		}
	}
}

sort($paths, SORT_STRING);

$output_directory = dirname($output);
if (! is_dir($output_directory) && ! mkdir($output_directory, 0775, true) && ! is_dir($output_directory)) {
	fwrite(STDERR, "Unable to create output directory.\n");
	exit(1);
}

$zip = new ZipArchive();
if (true !== $zip->open($output, ZipArchive::CREATE | ZipArchive::OVERWRITE)) {
	fwrite(STDERR, "Unable to open output ZIP.\n");
	exit(1);
}

foreach ($paths as $relative) {
	$name = 'checkout-firewall/' . str_replace(DIRECTORY_SEPARATOR, '/', $relative);
	if (! $zip->addFile($root . '/' . $relative, $name)) {
		fwrite(STDERR, "Unable to add: {$relative}\n");
		$zip->close();
		exit(1);
	}
	$zip->setMtimeName($name, CWF_PUBLIC_MIRROR_MTIME);
	$zip->setExternalAttributesName($name, ZipArchive::OPSYS_UNIX, 0100644 << 16);
}

if (! $zip->close()) {
	fwrite(STDERR, "Unable to finalize output ZIP.\n");
	exit(1);
}

printf("Built %s\nSHA-256 %s\n", $output, hash_file('sha256', $output));

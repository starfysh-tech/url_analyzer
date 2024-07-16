<?php
// Strict error reporting for development, adjust for production
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/path/to/error.log');  // Adjust this path

// Set secure headers
header("Content-Security-Policy: default-src 'self'");
header("X-XSS-Protection: 1; mode=block");
header("X-Frame-Options: SAMEORIGIN");
header("X-Content-Type-Options: nosniff");
header('Content-Type: application/json');

// Load environment variables
$dotenv = parse_ini_file('.env');
$max_redirects = $dotenv['MAX_REDIRECTS'] ?? 5;
$timeout = $dotenv['CURL_TIMEOUT'] ?? 10;

function unshorten_url($url) {
    global $max_redirects, $timeout;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_MAXREDIRS => $max_redirects,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'URLAnalyzer/1.0',
    ]);
    $response = curl_exec($ch);
    if(curl_errno($ch)) {
        throw new Exception(curl_error($ch));
    }
    $long_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    return $long_url;
}

function analyze_params($url) {
    $parsed_url = parse_url($url);
    if($parsed_url === false || !isset($parsed_url['query'])) {
        return [];
    }
    parse_str($parsed_url['query'], $params);
    
    $param_explanations = [
        'utm_medium' => 'Identifies what type of link was used',
        'utm_source' => 'Identifies which site sent the traffic',
        'utm_campaign' => 'Identifies a specific product promotion or strategic campaign',
        'utm_content' => 'Identifies what specifically was clicked to bring the user to the site',
        'utm_term' => 'Identifies search terms',
        'is_retargeting' => 'Indicates whether this is part of a retargeting campaign',
        'source_caller' => 'Identifies the source of the call to this URL',
        'shortlink' => 'The unique identifier for the shortened link',
        'c' => 'Often used as a campaign identifier (similar to utm_campaign)',
        'af_ad' => 'AppsFlyer parameter for ad identification',
        'pid' => 'Usually stands for Product ID or Partner ID',
        'af_xp' => 'AppsFlyer parameter for experience or experiment',
        'af_channel' => 'AppsFlyer parameter for marketing channel'
    ];

    $analyzed_params = [];
    foreach ($params as $key => $value) {
        $analyzed_params[$key] = [
            'value' => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            'explanation' => $param_explanations[$key] ?? 'Custom parameter'
        ];
    }

    return $analyzed_params;
}

function generate_yaml($params) {
    $yaml = "parameters:\n";
    foreach ($params as $key => $value) {
        $yaml .= "  " . addslashes($key) . ": \"" . addslashes($value['value']) . "\"\n";
    }
    return $yaml;
}

function handle_request() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        return json_encode(['error' => 'Method Not Allowed']);
    }

    $input = json_decode(file_get_contents('php://input'), true);
    $short_url = $input['url'] ?? '';

    if (empty($short_url) || !filter_var($short_url, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        return json_encode(['error' => 'Invalid URL provided']);
    }

    try {
        $full_url = unshorten_url($short_url);
        $params = analyze_params($full_url);
        $yaml = generate_yaml($params);

        return json_encode([
            'full_url' => $full_url,
            'params' => $params,
            'yaml' => $yaml,
        ]);
    } catch (Exception $e) {
        error_log("Error processing URL: " . $e->getMessage());
        http_response_code(500);
        return json_encode(['error' => 'An error occurred while processing the URL']);
    }
}

// Main execution
try {
    echo handle_request();
} catch (Exception $e) {
    error_log("Unhandled exception: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'An unexpected error occurred']);
}

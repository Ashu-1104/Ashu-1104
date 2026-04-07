<?php
/**
 * CSF HTML/UI Helper Module
 * Functions for rendering web interface components
 */

/**
 * Get page header
 * 
 * @param string $title Page title
 * @return string
 */
function csf_html_header($title = 'CSF Control Panel') {
    $html = '<!DOCTYPE html>' . "\n";
    $html .= '<html lang="en">' . "\n";
    $html .= '<head>' . "\n";
    $html .= '<meta charset="UTF-8">' . "\n";
    $html .= '<meta name="viewport" content="width=device-width, initial-scale=1.0">' . "\n";
    $html .= '<title>' . htmlspecialchars($title) . '</title>' . "\n";
    $html .= '<link rel="stylesheet" href="/csf/css/style.css">' . "\n";
    $html .= '</head>' . "\n";
    $html .= '<body>' . "\n";
    
    return $html;
}

/**
 * Get page footer
 * 
 * @return string
 */
function csf_html_footer() {
    $html = '<script src="/csf/js/script.js"></script>' . "\n";
    $html .= '</body>' . "\n";
    $html .= '</html>' . "\n";
    
    return $html;
}

/**
 * Render status badge
 * 
 * @param bool $status Status
 * @param string $true_text True text
 * @param string $false_text False text
 * @return string
 */
function csf_html_status_badge($status, $true_text = 'Enabled', $false_text = 'Disabled') {
    $class = $status ? 'badge-success' : 'badge-danger';
    $text = $status ? $true_text : $false_text;
    
    return '<span class="badge ' . $class . '">' . htmlspecialchars($text) . '</span>';
}

/**
 * Render alert box
 * 
 * @param string $type Alert type (success, danger, warning, info)
 * @param string $message Message
 * @param bool $dismissible Dismissible
 * @return string
 */
function csf_html_alert($type, $message, $dismissible = true) {
    $html = '<div class="alert alert-' . htmlspecialchars($type) . '"';
    
    if ($dismissible) {
        $html .= ' role="alert">';
        $html .= '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
    } else {
        $html .= '>';
    }
    
    $html .= htmlspecialchars($message);
    $html .= '</div>' . "\n";
    
    return $html;
}

/**
 * Render button
 * 
 * @param string $text Button text
 * @param string $url Button URL
 * @param string $type Button type (primary, danger, success, etc.)
 * @param array $attributes Additional attributes
 * @return string
 */
function csf_html_button($text, $url = '#', $type = 'primary', $attributes = array()) {
    $attrs = ' class="btn btn-' . htmlspecialchars($type) . '"';
    
    if (isset($attributes['class'])) {
        $attrs = ' class="btn btn-' . htmlspecialchars($type) . ' ' . htmlspecialchars($attributes['class']) . '"';
        unset($attributes['class']);
    }
    
    foreach ($attributes as $key => $value) {
        $attrs .= ' ' . htmlspecialchars($key) . '="' . htmlspecialchars($value) . '"';
    }
    
    return '<a href="' . htmlspecialchars($url) . '"' . $attrs . '>' . htmlspecialchars($text) . '</a>';
}

/**
 * Render table header
 * 
 * @param array $columns Column headers
 * @return string
 */
function csf_html_table_header($columns) {
    $html = '<thead class="table-dark">' . "\n";
    $html .= '<tr>' . "\n";
    
    foreach ($columns as $column) {
        $html .= '<th>' . htmlspecialchars($column) . '</th>' . "\n";
    }
    
    $html .= '</tr>' . "\n";
    $html .= '</thead>' . "\n";
    
    return $html;
}

/**
 * Render table row
 * 
 * @param array $cells Cell contents
 * @return string
 */
function csf_html_table_row($cells) {
    $html = '<tr>' . "\n";
    
    foreach ($cells as $cell) {
        $html .= '<td>' . htmlspecialchars($cell) . '</td>' . "\n";
    }
    
    $html .= '</tr>' . "\n";
    
    return $html;
}

/**
 * Render form field
 * 
 * @param string $type Field type (text, password, email, etc.)
 * @param string $name Field name
 * @param string $label Field label
 * @param string $value Field value
 * @param array $attributes Additional attributes
 * @return string
 */
function csf_html_form_field($type, $name, $label, $value = '', $attributes = array()) {
    $html = '<div class="mb-3">' . "\n";
    $html .= '<label for="' . htmlspecialchars($name) . '" class="form-label">' . htmlspecialchars($label) . '</label>' . "\n";
    $html .= '<input type="' . htmlspecialchars($type) . '" class="form-control"';
    $html .= ' id="' . htmlspecialchars($name) . '" name="' . htmlspecialchars($name) . '"';
    
    if (!empty($value)) {
        $html .= ' value="' . htmlspecialchars($value) . '"';
    }
    
    foreach ($attributes as $key => $val) {
        $html .= ' ' . htmlspecialchars($key) . '="' . htmlspecialchars($val) . '"';
    }
    
    $html .= '>' . "\n";
    $html .= '</div>' . "\n";
    
    return $html;
}

/**
 * Render select field
 * 
 * @param string $name Field name
 * @param string $label Field label
 * @param array $options Options (value => label)
 * @param string $selected Selected value
 * @return string
 */
function csf_html_form_select($name, $label, $options, $selected = '') {
    $html = '<div class="mb-3">' . "\n";
    $html .= '<label for="' . htmlspecialchars($name) . '" class="form-label">' . htmlspecialchars($label) . '</label>' . "\n";
    $html .= '<select class="form-select" id="' . htmlspecialchars($name) . '" name="' . htmlspecialchars($name) . '">' . "\n";
    
    foreach ($options as $value => $label_text) {
        $sel = ($value === $selected) ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars($value) . '"' . $sel . '>' . htmlspecialchars($label_text) . '</option>' . "\n";
    }
    
    $html .= '</select>' . "\n";
    $html .= '</div>' . "\n";
    
    return $html;
}

/**
 * Render textarea field
 * 
 * @param string $name Field name
 * @param string $label Field label
 * @param string $value Field value
 * @param int $rows Number of rows
 * @return string
 */
function csf_html_form_textarea($name, $label, $value = '', $rows = 5) {
    $html = '<div class="mb-3">' . "\n";
    $html .= '<label for="' . htmlspecialchars($name) . '" class="form-label">' . htmlspecialchars($label) . '</label>' . "\n";
    $html .= '<textarea class="form-control" id="' . htmlspecialchars($name) . '" name="' . htmlspecialchars($name) . '"';
    $html .= ' rows="' . (int)$rows . '">' . htmlspecialchars($value) . '</textarea>' . "\n";
    $html .= '</div>' . "\n";
    
    return $html;
}

/**
 * Render checkbox field
 * 
 * @param string $name Field name
 * @param string $label Field label
 * @param bool $checked Checked status
 * @return string
 */
function csf_html_form_checkbox($name, $label, $checked = false) {
    $html = '<div class="form-check">' . "\n";
    $html .= '<input class="form-check-input" type="checkbox" id="' . htmlspecialchars($name) . '"';
    $html .= ' name="' . htmlspecialchars($name) . '" value="1"';
    
    if ($checked) {
        $html .= ' checked';
    }
    
    $html .= '>' . "\n";
    $html .= '<label class="form-check-label" for="' . htmlspecialchars($name) . '">' . htmlspecialchars($label) . '</label>' . "\n";
    $html .= '</div>' . "\n";
    
    return $html;
}

/**
 * Render modal dialog
 * 
 * @param string $id Modal ID
 * @param string $title Modal title
 * @param string $body Modal body content
 * @param array $buttons Buttons (text => onclick)
 * @return string
 */
function csf_html_modal($id, $title, $body, $buttons = array()) {
    $html = '<div class="modal fade" id="' . htmlspecialchars($id) . '" tabindex="-1">' . "\n";
    $html .= '<div class="modal-dialog">' . "\n";
    $html .= '<div class="modal-content">' . "\n";
    
    // Header
    $html .= '<div class="modal-header">' . "\n";
    $html .= '<h5 class="modal-title">' . htmlspecialchars($title) . '</h5>' . "\n";
    $html .= '<button type="button" class="btn-close" data-bs-dismiss="modal"></button>' . "\n";
    $html .= '</div>' . "\n";
    
    // Body
    $html .= '<div class="modal-body">' . "\n";
    $html .= $body . "\n";
    $html .= '</div>' . "\n";
    
    // Footer
    if (!empty($buttons)) {
        $html .= '<div class="modal-footer">' . "\n";
        
        foreach ($buttons as $text => $onclick) {
            $html .= '<button type="button" class="btn btn-primary" onclick="' . htmlspecialchars($onclick) . '">';
            $html .= htmlspecialchars($text) . '</button>' . "\n";
        }
        
        $html .= '</div>' . "\n";
    }
    
    $html .= '</div>' . "\n";
    $html .= '</div>' . "\n";
    $html .= '</div>' . "\n";
    
    return $html;
}

/**
 * Render stats card
 * 
 * @param string $title Card title
 * @param string $value Card value
 * @param string $icon Card icon class
 * @param string $type Card type (primary, success, danger, warning)
 * @return string
 */
function csf_html_stats_card($title, $value, $icon = '', $type = 'primary') {
    $html = '<div class="card border-' . htmlspecialchars($type) . ' mb-3">' . "\n";
    $html .= '<div class="card-body">' . "\n";
    
    if (!empty($icon)) {
        $html .= '<i class="' . htmlspecialchars($icon) . '"></i> ';
    }
    
    $html .= '<h6 class="card-title">' . htmlspecialchars($title) . '</h6>' . "\n";
    $html .= '<h4 class="text-' . htmlspecialchars($type) . '">' . htmlspecialchars($value) . '</h4>' . "\n";
    $html .= '</div>' . "\n";
    $html .= '</card>' . "\n";
    
    return $html;
}

/**
 * Render breadcrumb navigation
 * 
 * @param array $items Breadcrumb items (label => url)
 * @return string
 */
function csf_html_breadcrumb($items) {
    $html = '<nav aria-label="breadcrumb">' . "\n";
    $html .= '<ol class="breadcrumb">' . "\n";
    
    foreach ($items as $label => $url) {
        if ($url === '#') {
            $html .= '<li class="breadcrumb-item active" aria-current="page">' . htmlspecialchars($label) . '</li>' . "\n";
        } else {
            $html .= '<li class="breadcrumb-item"><a href="' . htmlspecialchars($url) . '">' . htmlspecialchars($label) . '</a></li>' . "\n";
        }
    }
    
    $html .= '</ol>' . "\n";
    $html .= '</nav>' . "\n";
    
    return $html;
}

/**
 * Escape HTML
 * 
 * @param string $text Text to escape
 * @return string
 */
function csf_html_escape($text) {
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

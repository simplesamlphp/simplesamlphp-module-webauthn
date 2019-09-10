<?php
function warn($text) {
    global $validatebuffer;
    $validatebuffer .= "<span style='background-color:yellow;'>WARN: $text</span><br/>";
}

function fail($text) {
    global $validatebuffer;
    global $debugbuffer;
    global $debugEnabled;
    $validatebuffer .= "<span style='background-color:red;'>FAIL: $text</span><br/>";
    if ($debugEnabled) {
        echo $debugbuffer;
        echo $validatebuffer;
    }
    throw new Exception($text);
}

function pass($text) {
    global $validatebuffer;
    $validatebuffer .= "<span style='background-color:green; color:white;'>PASS: $text</span><br/>";
}

function ignore($text) {
    global $validatebuffer;
    $validatebuffer .= "<span style='background-color:blue; color:white;'>IGNORE: $text</span><br/>";
}

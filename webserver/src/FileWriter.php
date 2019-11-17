<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 07/11/19
 * Time: 10:16
 */

namespace App;


class FileWriter
{
    public const TMP_DIRECTORY = "/tmp";

    public function __construct()
    {
    }

    public function write($filename, $data)
    {
        $file = fopen($filename, "w") or die("Unable to open file!");
        fwrite($file, $data);
        fclose($file);
    }
}
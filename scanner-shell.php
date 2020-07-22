<?php

//configuration

$configue['target_dir'] = "/home";
$configue['output_file'] = "output/results_".date("Y-m-d").".txt";
$configue['false_positives_file'] = "false_positives.txt";
$configue['email'] = ""; //votre email

// les fichiers sont suspects s'ils contiennent l'une de ces chaînes.

$suspicious_strings = array(
    'c99shell', 'shell', 'phpspypass', 'Owned',
    'hacker', 'h4x0r', '/etc/passwd',
    'uname -a', 'eval(base64_decode(',
    '(0xf7001E)?0x8b:(0xaE17A)',
    'd06f46103183ce08bbef999d3dcc426a',
    'rss_f541b3abd05e7962fcab37737f40fad8',
    'r57shell',
    'Locus7s',
    'milw0rm.com',
    '$IIIIIIIIIIIl',
    'SubhashDasyam.com',
    '31337');
$suspicious_files = array();


//faux positifs

if(file_exists($configue['false_positives_file'])){
$content =  file_get_contents($configue['false_positives_file']);
$false_positives = explode("\n", $contents);
}else{

    $false_positives = false;

}

//analyser de manière récursive un répertoire à la recherche de logiciels malveillants

function php_file($filename){
    return substr($filename, -4) == ".php" || substr($filename, -5) == ".php5";

}

//scanne récursivement un répertoire pour les fichier malveillants

$dir_count = 0;
function scan_shell($path){
    global $suspicious_strings;
    global $suspicious_files;
    global $configue;
    global $false_positives;
    global $dir_count;
    echo ".";
    $dir_count++;

    // on ouvre le fichier
    $fichier = @dir($path);
    if($fichier == false){
    echo "\n[] Échec de l'ouverture du répertoire ".$path.", saute";
    return;
  }
  while(false !== ($filename = $fichier->read())){
      if($filename != "." && $filename != ".."){
        $full_filename = $fichier->path."/".$filename;

        $false = false;
            if($false_positives) {
                if(in_array($full_filename, $false_positives))
                    $false = true;
            }
            if(!$false) {
                //est-ce un autre répertoire?
                if(is_dir($full_filename)) {
                    // scannez-le
                    scan_shell($full_filename);
                } else {        
                    // est-ce un fichier php?
                    if(php_file($filename)) {
                        // analyser ce fichier
                        $contents = file_get_contents($full_filename);
                        $suspicious = false;
                        foreach($suspicious_strings as $string) {
                            if(strpos(strtolower($contents), strtolower($string)) != false)
                                $suspicious = true;
                        }
                        if($suspicious) {
                            // trouvé un fichier suspect!
                            echo "\n[] *** Fichier suspect trouvé : ".$full_filename;
                            
                            // enregistrez-le dans le fichier de sortie
                            // note: J'ouvre et ferme ce fichier à chaque fois afin que vous puissiez voir le fichier avant que l'analyse complète ne soit terminée
                            $of = fopen($configue['output_file'], "a");
                            fwrite($of, $full_filename."\n");
                            fclose($of);

                            //enregistrez-le le tableau
                            $suspicious_files[] = $full_filename;
                        }
                    }
                }
            }
        }
    }
}
?>

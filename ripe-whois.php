<?php

/**
 * http://pwhois.org/ris.who
 *
 *  RIPE NCC RIS WHOIS Bulk Query Interface
 *
 *  -- a native interface to RIS WHOIS implemented in PHP*
 *
 *                                        * requires PHP >= 5
 *
 *  Simply call doRISLookupBulk(array $queryArray) and it will
 *  return an associative array of AS numbers (and other data
 *  indexed by the IP addresses passed to it in the $queryArray 
 *  argument.
 *                               -- by Victor Oppleman (2005)
 */

function doRISLookupBulk($queryarray) {

	$risserver = 'riswhois.ripe.net'; // RIPE NCC RISwhois Server (public)
	$risport = 43;                    // Port to which RIPE NCC RISwhois listens
	$socket_timeout = 20;             // Timeout for socket connection operations
	$socket_delay = 5;                // Timeout for socket read/write operations
	$buffer = '';

	// Mostly generic code beyond this point
	$risserver = gethostbyname($risserver);

	// Optimize query array and renumber
	$queryarray = array_unique($queryarray);
	$i = 0;
	foreach ($queryarray as $a) { 
		$qarray[$i] = $a;
		$i++;
	}


	// Create a new socket
	$sock = stream_socket_client("tcp://".$risserver.":".$risport, 
	$errno, $errstr, $socket_timeout);
	if (!$sock) {
		// echo "$errstr ($errno)<br />\n";
		return 0;
	} else {

		stream_set_blocking($sock,0);         // Set stream to non-blocking
		stream_set_timeout($sock, $socket_delay); // Set stream delay timeout

		// Build, then submit bulk query
		$request = "-k -1 -M\n";
		foreach ($qarray as $addr) {
			$request .= $addr . "\n";
		}
		$request .= "-k\n";
		fwrite($sock, $request);

		// Keep looking for more responses until EOF or timeout
		$before_query = date('U');
		while(!feof($sock)){
			if($buf=fgets($sock,128)){
				$buffer .= $buf;
				if (date('U') > ($before_query + $socket_timeout)) break;
			}
		}

		fclose($sock);

		$response = array();
		$resp = explode("\n",$buffer);
		$entity_id = 0; $found = 0;
		foreach ($resp as $r) {
			$matcher = '';

			if (preg_match('/route:\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i',$r,$matcher)) {
			if ($found > 0) { $entity_id++; $found = 0; }
				$response[$qarray[$entity_id]]['route'] = $matcher[1];
				$found++;

			} else if (preg_match('/origin:\s+AS(\d+)/i',$r,$matcher)) {
				$response[$qarray[$entity_id]]['origin'] = $matcher[1]; 

			} else if (stristr($r,'descr')) {
				$matcher = explode(":",$r);
				$response[$qarray[$entity_id]][$matcher[0]] = ltrim($matcher[1]);

			} else if (stristr($r,'lastupd-frst')) {
				$matcher = explode(":",$r);
				$response[$qarray[$entity_id]][$matcher[0]] = ltrim($matcher[1]);

			} else if (stristr($r,'lastupd-last')) {
				$matcher = explode(":",$r);
				$response[$qarray[$entity_id]][$matcher[0]] = ltrim($matcher[1]);

			} else if (stristr($r,'seen-at')) {
				$matcher = explode(":",$r);
				$response[$qarray[$entity_id]][$matcher[0]] = ltrim($matcher[1]);

			} else if (stristr($r,'num-rispeers')) {
				$matcher = explode(":",$r);
				$response[$qarray[$entity_id]][$matcher[0]] = ltrim($matcher[1]);

			} else if (stristr($r,'source')) {
				$matcher = explode(":",$r);
				$response[$qarray[$entity_id]][$matcher[0]] = ltrim($matcher[1]);

			} else if (stristr($r,'Error')) {   
				// return zero if no asn
				$found++;
			}

			if ($entity_id >= array_count_values($qarray)) break;

		} //end foreach

		return $response;

	} //end elf

} //end if



if(!$_GET)
{
	echo "
<br /><br />
<center>
	<form action='?' method='get'>
		IP: <input type='text' name='ip' />
		    <input type='submit' name='gonder' value='Gonder' />
	</form>
</center>
	";

} else {


	$sonuc = doRISLookupBulk( array( $_GET['ip'] ) );
	if(!$sonuc)
		die('Sonuc bulunamadi!');
	else {
		echo "<pre>";
		print_r($sonuc);
		echo "\n\nNOT: http://data.ris.ripe.net/[seen-at]</pre>";
	}

}

/*
  // An example of calling the function... and the results it returns:

  $test_array = array('4.2.2.1','12.0.0.0');
  if (!($risresp = doRISLookupBulk($test_array))) {
          print "<h2>Your query wasn't answered.</h2>\n";
          exit();
  }

  print "<pre>";
  foreach ($risresp as $ip => $resp) {
    print "IP: " . $ip . "<br />";
    print_r($resp);
    print "<br />";
  }
  print "</pre>";
*/
?>

#!/usr/bin/perl -w 

use strict;
use warnings;
use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha384 sha512 sha512_hex sha512_base64 sha256 sha256_hex sha256_base64 hmac_sha256 hmac_sha256_base64 hmac_sha256_hex hmac_sha512 hmac_sha512_base64);
use MIME::Base64;
use Crypt::CBC qw(random_bytes);


## The utterly protopandemonic Analmaggedonical 'KeithAlexanderLovesCocks' function ##

sub KeithAlexanderLovesCocks {
	
	my @dat = @_;
	
	my $d1  = sha512(sha512(sha512($dat[0])));
	my $mk1 = sha256(sha256($d1));
	my $d2  = sha512(sha384(sha256($dat[0])));
	my $mk2 = sha256(sha256($d2));
	
	my $hm1 = sha512(hmac_sha512($d2,$mk1));
	my $hm2 = sha512(hmac_sha512($d1,$mk2));
	
	my $hm  = $hm1 ^ $hm2;
	
	my $mx  = $d1  ^ $d2;
	   $mx  = $mx  ^ $hm;
	my $mk  = $mk1 ^ $mk2;
	
	   $mx  = sha512(hmac_sha512($mx,$mk));
	
	my $dkA = sha512_base64(hmac_sha512($mx,$mk));
	my $dkB = sha512_base64(sha384(hmac_sha512($mx,$mk)));
	
    my $dk  = sha512_base64(hmac_sha512($dkA,$dkB));
	
	return ($dk,$dkA,$dkB);
}

## < kayla> lol


my @args = @ARGV;

if ( !($args[0] =~ m/^(-e|-d)$/ ) || !$args[1] || !$args[2] ) {
	
    print ("noNSA is a simple PoC to encrypt files with Camellia-256, \n");
    print ("providing good verbose, HMAC of files, and deploying the\n");
    print ("KeithAlexanderLovesCocks function to derive stronger \n");
    print ("passphrases (or seeds) from the given ones, before the key derivation step. \n\n");
	print ("Usage: nonsa <-e|-d> <password> FILE \n\n");
	print ("-e  to encrypt a file \n");
	print ("-d  to decrypt a file \n");
	print ("<password> means..err.well..that you need to give the passphrase to use \n");
	print ("FILE means..well..the name of the file you want to encrypt or decrypt... \n\n");	
	
	}else{
	 

 if (!( -e $args[2])) {
	  
    print("$args[2] : File not found. \n");
    exit;
    
   }else{
 
	    
	    my ($penis,$penis2,$penis3) = KeithAlexanderLovesCocks($args[1]);
	
	
	    my $cipher = Crypt::CBC->new(
	         {    
	           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
	
	       #   'cipher'        => 'Rijndael',                              # change this if you want to use AES instead Camellia, 
	                                                                       # but we suggest to stick to Camellia, Camellia requires Crypt::Camellia
	          # 'cipher'        => 'Camellia',
		      'cipher'        => 'Camellia_PP',                           # Optionally you could use the pure perl implementation of Camellia in case
                                                                           # you need it, considering the performance cost that implies.
	           'padding'       => 'standard',
	    
	           'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
	         }
	        );
	    
	   
	    $cipher->{'passphrase'} = $penis;
	    
	    if ( $args[0] eq '-e' ) {
			
		      my $buffer;
		      $cipher->start('encrypting');
	          open(F,"<$args[2]") or die "cannot open file $args[2]" ;
	          open(T,">$args[2].crypt") or die "cannot open file $args[2].crypt";
	          while (read(F,$buffer,1024)) {
	
	            print T $cipher->crypt($buffer);
	
	
	          }
	          
	          print T $cipher->finish;
	          close(T);
	          close(F);
		              
		           
	        my $algo = $cipher->{cipher};
		    $algo =~ s/Crypt::// ;
		    print "Algorithm : " . $algo . "    Keysize: " . int($cipher->{keysize}) *  8 . "bits   Blocksize: " . int($cipher->{blocksize}) * 8 . "bits \n\n" ;
		    print "passphrase : " . $args[1] . " \n";
		    
		    if ( ($cipher->{fuckNSA}) and ($cipher->{fuckNSA} == 1) ) {
				print "fuckNSA enabled : yes \n";
			}else{
				print "fuckNSA enabled : no \n";
			}
		    
		    print "salt : " . unpack("H*",$cipher->{'salt'}) ." \n";
		    print "key  : " . unpack("H*",$cipher->{'key'}) ." \n";
		    print "iv   : " . unpack("H*",$cipher->{'iv'}) ." \n";
		    print "KALC derived proto-Key seed : $cipher->{'passphrase'} \n\n";
		    print "Encrypted output file is : $args[2].crypt \n\n";
		    
		    my $file;
		    open(F,"<$args[2]") or die "cannot open file $args[2]";
	         {
	            local $/;
	            $file = <F>;
	          }
	          close(F);
		    print ("HMAC (SHA256) for unencrypted File: " . hmac_sha256_hex($file,substr($penis3,0,32)) . " \n");
		    print ("KALC derived HMAC key: " . substr($penis3,0,32) . " \n");
		    
	    }
	    if ( $args[0] eq '-d' ) {
			
			my $fname = $args[2];
			$fname =~ s/\//_/g ;
			$fname =~ s/^/decrypted_/ ;
			$fname =~ s/\.crypt$// ;
	        # lol. that was really lazy
	
		    
		      my $buffer;
		      $cipher->start('decrypting');
	          open(F,"<$args[2]");
	          open(D,">$fname") or die "cannot open file $fname";;
	          while (read(F,$buffer,1024)) {
	
	              print D $cipher->crypt($buffer);
	
	
	          }
	
	          print D $cipher->finish();
	          
	          close(D);
	          close(F);
	        
	        my $algo = $cipher->{cipher};
		    $algo =~ s/Crypt::// ;  ## perhaps not needed...
		    print "Algorithm : " . $algo . "    Keysize: " . int($cipher->{keysize}) *  8 . "bits   Blocksize: " . int($cipher->{blocksize}) * 8 . "bits \n\n" ;  
		    print "passphrase : " . $args[1] . " \n";
		    print "salt : " . unpack("H*",$cipher->{'salt'}) ." \n";
		    print "key  : " . unpack("H*",$cipher->{'key'}) ." \n";
		    print "iv   : " . unpack("H*",$cipher->{'iv'}) ." \n";
		    print "KALC derived proto-Key seed : $cipher->{'passphrase'} \n\n";
			print ("Decrypted output file is : $fname \n\n");
			
			## This is optional if you don't need it or it annoys you cause the memory thingie on big files just comment it out ##
			my $file;
		    open(F,"<$fname") or die "cannot open file $fname";
	         {
	            local $/;
	            $file = <F>;
	          }
	          close(F);
	          
		    print ("HMAC for unencrypted File: " . hmac_sha256_hex($file,substr($penis3,0,32)) . " \n");
		    print ("KALC derived HMAC key: " . substr($penis3,0,32) . " \n");
		    ## hmac stuff ends here ##
		}
    
  }

}







use strict;
use warnings;
use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha384 sha512 sha512_hex sha512_base64 sha256 sha256_hex sha256_base64 hmac_sha256 hmac_sha256_base64 hmac_sha256_hex hmac_sha512 hmac_sha512_hex hmac_sha512_base64);
use Crypt::CBC;
use MIME::Base64;
use Compress::Zlib;
use POSIX;
use Irssi::Irc;
use Irssi;
use vars qw($VERSION %IRSSI $cipher);

## ----------------------------------------------------------------------
## ##  "There come a time, when good men must wear mask.....kemosabe"  ##
## ----------------------------------------------------------------------
##    _  _                  __  .__                      
## __| || |_______    _____/  |_|__| ______ ____   ____      #FREEHAMMOND
## \   __   /\__  \  /    \   __\  |/  ___// __ \_/ ___\     #FREEASSANGE
##  |  ||  |  / __ \|   |  \  | |  |\___ \\  ___/\  \___     #FREECHELSEA
## /_  ~~  _\(____  /___|  /__| |__/____  >\___  >\___  >    #FREESNOWDEN
##   |_||_|       \/     \/             \/     \/     \/     #FREELULZSEC
## 
## ----------------------------------------------------------------------
## ----------------------------------------------------------------------
## ## the best trick ever pulled was to convince FBI they can catch us ##
## ----------------------------------------------------------------------
## ----------------------------------------------------------------------
#
#    WHAT THE FUCK fuckNSA.pl DOES????  ..mpOTR man, its all about mpOTR
#    ---------------------------------
#    
#    it implements advanced encryption over IM/IRC communications resolving 
#    the how-sharing-the-fucking-passphrase problem & deploying an inspired OTRv2 
#    key exchange agreement. it uses Camellia256, DH keys of 4096 bits, RSA 
#    keys of 4096 bits and sha512, sha256, etc. it produces 2 keys: one for encrypted
#    communications and the second one to use on file encryption (in case
#    ppl needs to share stuff) it implements a flexible mpOTR solution, flexible
#    enough to be quicky hackable, letting a group of ppl on a given channel for 
#    example to exclude a non-trusted part (aka FBI snitch) from knowing other keys 
#    used for that channel, the use of temporary common keys to reduce flooding, the use 
#    of individual keys and whatever u prefer to do. If a computer belonging to
#    some individual is seized by FBI, only the last keys used would be compromised and only
#    those ones shared with some individuals for that last conversation that individual
#    has participated, therefore not compromising conversations that happened between 
#    other individuals on the same channel at different times. Users retain full control of the 
#    decisions to make. the DH parameters are easy to change, so different 
#    groups can easily employ their own parameters with keys of 16384 bits for example. 
#    it offers good verbosity and keep history of your peer's fingerprints in case 
#    you need to check it, when you go full paranoid, and many other etc & etc...
#
#    it needs Crypt::CBC (recommended to install the antisec modded Crypt::CBC)
#    also needs Crypt::Camellia_PP (Crypt::Camellia would perform faster)
#    check your OpenSSL too.
#
#    for quick install:
#    copy CBC.pm and Camellia_PP.pm to folder 'Crypt' where your other perl modules are
#
#    original repository https://github.com/j0hnnMcCock/fuckNSA
#
#    for more information
#	1 READ THE FUCKING CODE
#	2 READ THE FUCKING CODE
#	3 READ THE FUCKING CODE
#	4 IMPROVE IT AND ENJOY IT
#
#    about performance: hacker teams working on stuff usually are composed by small groups of
#    people, for crowded channels probably it would be better to use a general key to avoid 
#    flooding and because secrecy on crowded channels (in practice) is compromised by default anyways.
#
#    LICENSE
#    -------
# 
#    ##############################################
#    ##             LulzSec License              ##
#    ##                                          ##
#    ## Do whatever you fucking want with this,  ##
#    ## but you must produce at least one act of ##
#    ## civil disobedience against the System    ##
#    ## and its rules, even if that represents   ##
#    ## not honoring this license at all.        ##
#    ## Fuck Cops' daughters, send cigarettes    ##
#    ## to those of us who are jailed, smash     ##
#    ## down CCTV cameras and...                 ##
#    ## also cocks, because lulz.                ##
#    ##                                          ##
#    ##############################################
#
#  SHA256SUMs
#
#  77c3c8cca0476965e82327c55e136b09e1cb876ca4bb333dfa538b5ad4818af9  Camellia_PP.pm
#  5b24c307141d78b8224a21f3abd1efb099bdc821709520349bfa6b31bb241644  CBC.pm
#
#  43f50d2faa7fc28ca2a0267fa7456a0bdf5eec16e0cb84842166dbd242d20e0a  libcrypt-camellia-perl_2.02-1_all.deb
#  e137d9b335facb9aeaa7c77b424f8414c970a01e406d4a14b3b81c1b2b267344  libcrypt-camellia-perl_2.02-1_amd64.deb
#  e3df84cfa22eb4d980317faf1e03cd567c0cdc80e1209ab7809418d1f74a980f  libcrypt-camellia-pp-perl_0.02-1_all.deb
#  74cf6b69cbd379566168e5ae605317e7c935d04023fe9fae52ae0fd01cb1a9c8  libcrypt-cbc-perl_2.33-1_Lulzsec-mod_all.deb
#
#
#    bitcoins to: 1KrvDzgWrzJeWjzEDPnxziUJbrPNKpS3bs
#
#    2013. All Your Base Are Belong To Us
#
#

$VERSION = "0.7.2";
%IRSSI = (
    authors => 'gcu-squad, LulzSec, AntiSec',
    contact => '#anonops@anonops (just cry there: poke is fat )',
    name => 'fuckNSA',
    description => 'Crypt IRC and IM communications using Camellia256 encryption with OTRv2 inspired Key Exchange Agreement, includes mpOTR implementation and file encryption(separated bonus). Supports public #channels, !channels, +channel, querys and dcc chat. Join #anonops @ irc.anonops.com to get latest p0rn available.',
    license => 'LulzSec License',
    url => 'The Antisec Embassy: http://ibhg35kgdvnb7jvw.onion',
);

############# IRSSI README AREA #################################
#To install this script just do
#/script load ~/fuckNSA.pl
#  and
#/fucknsahelp
#  to read all the complete features of the script 
#To uninstall it do
#/script unload fuckNSA
################################################################


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

## ATTENTION HERE, if you need to switch between Camellia_PP (pure perl) and Camellia (c) or Rijndael (AES) modify here the 'cipher' algorithm ##
 
my $cipher = Crypt::CBC->new(
  {    
    'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',       
																 
                                                                 
   #'cipher'        => 'Camellia',                               
   'cipher'        => 'Camellia_PP',                  # Optionally you could use the pure perl implementation of Camellia in case
                                                       # you need it.                                                                
                                                                 
    'padding'       => 'standard',
    
    'fuckNSA'       => 1,                                      
                                                                 
                                                                 
                                                                 
                                                                 
  }
);




my $key = 'pcZZO@YG3r70+O#oHci$u-H#iPcq&_6g.4^/' ; # the default key. dont rely on this other than for testing pl0x

my $header = "{fuckNSA_";
my $DHinit = "{fuckNSAANNCD}";
my $DHinit2 = "{fuckNSA-ANNCD-";
my $answDHinit = "{fNSAOK-";
my $DHgimmePubheader = "{fNSAGVP-";
my $DHgimmeFiveBroheader = "{fNSAGFP-";
my $DHstuffIncomingheader = "{fNSAINP-";
my $DHgimmetheCandy = "{fNSACDY-";

my (%candidatesharedsecret);


my $debugging = 0;


my $paranoia = 1;

my $enableWildcard="yes";


my (%AKE);

my $alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

my $gkey;

my $folder =Irssi::get_irssi_dir()."/fuckNSA/";
my $friendsfolder = Irssi::get_irssi_dir()."/fuckNSA/friends/";
my $convofolder = Irssi::get_irssi_dir()."/fuckNSA/convos/";
my $errorlog = Irssi::get_irssi_dir()."/fuckNSA/errorlog";

my @key2use;



 umask(0077);

sub loadconf
{
	
	mkdir($folder, 0700) unless(-d $folder );
	mkdir($friendsfolder, 0700) unless(-d $friendsfolder );
    mkdir($convofolder, 0700) unless(-d $convofolder );

	
  my $fconf =Irssi::get_irssi_dir()."/fuckNSA/fuckNSA.conf";
  
  if ( !( -e $fconf ) ) {
	 Irssi::print("\00305> $fconf not found, setting to defaults\n");
     Irssi::print("\00305> creating $fconf with default values\n\n");
	open(CONF,">$fconf");
    print CONF "key:			$key\n";
    print CONF "header:			$header\n";
    print CONF "wildcardserver:		$enableWildcard\n";
    close(CONF);
	  
  }
  
  my @conf;
  open (CONF, "<$fconf");
  @conf=<CONF>;
  close(CONF);
  
  
  
  ## default dh params - GUISE! drop your own dh parameters here if you want new defaults for this ##
  ## but remember everyone communicating with you must generate their keys using the same shared parameters ##
  
  my $dhparamsfile = Irssi::get_irssi_dir()."/fuckNSA/dh-4096.pem";

  if ( !( -e $dhparamsfile) ) {
	  Irssi::print("\00305> $dhparamsfile not found, creating one with default parameters\n");
	  Irssi::print("\00305> Creating default DH parameters file \n");
	open(DHPF,">$dhparamsfile");
    print DHPF "-----BEGIN DH PARAMETERS-----\n";
    
    print DHPF "MIICCAKCAgEAziw5ivsQ1B+o+7uHHT0tQhlCNit0GQLIOFZSTgseYRykz9EKBZ/4\n";
    print DHPF "YuNbmZXm5Zb9z4ggCJjI5MKUsFSiNIrvgi6+DZBm3FL0IRCd6E81s8/wwZRj9Mup\n";
    print DHPF "ECvtg9M4+rHQmmM2SS8aZZLEn8r2yDSVi2nJ7u68bq2uDtPA73z9BGhbME0y6kOZ\n";
    print DHPF "AfcumA/EHXfIXroTZr/OgX8yupMFUKJsWWRxz1ynfl/avk4/fR0fSAxNE/XRPIWw\n";
    print DHPF "e1GhX3iIbghSm0cQF3QYiLe+hV4ZottMMv0NiT6drGTmY+pbTPViWW7dA5H3+ECt\n";
    print DHPF "n+3jAwjcHkTMGvpNjlseYMXgoM8bwq5cXND4vT42mTctrdExF9tHZ063L2PGTuj2\n";
    print DHPF "ixNzdVV/9J0x+sQx1ehTmem97LSS/sDEoVCutq919+OGW8zUEg3fVi5+7sMLJYb+\n";
    print DHPF "FIgRCDDo0pvt6ChhO9rZO06WcgA0JXlG8W503jDWPjKL8XiE4hB+UnwOTKQwWnU4\n";
    print DHPF "lmAAREYEMRBS/ocrIz5NumLgMSsCRdqrfg6jj/ygcQ97CSwtUoc7Pc/VrWC6gJ/w\n";
    print DHPF "7RLwr3NccbUwcoKNpBDJrX8jj5jaYqK0G1eeT0gECHmQBCjHflRll+Lzic/EwScH\n";
    print DHPF "VZ3akvR/J91l+5XKKN3DFZjldalSd0W8Mu6nHnOaRAOP6hNm0oW3naMCAQI=\n";

    print DHPF "-----END DH PARAMETERS-----\n";
    close(DHPF);
  }
  ## ##
  
  my $privateRSAkey = Irssi::get_irssi_dir()."/fuckNSA/RSAprivateKey";
  if ( !( -e $privateRSAkey) ) {
	  Irssi::print("\00305> $privateRSAkey not found, setting to create new one\n");
	  Irssi::print("\00305> Generating your Private RSA key \n");
	  my $creatersaprv;
	  eval{$creatersaprv = `openssl genrsa -out "$privateRSAkey" -rand /dev/urandom 4096 2>>$errorlog`};
	  if ($@) {
		  	 Irssi::print("\00305> Something went wrong generating it, please retry later. ");

	  }else {
		  Irssi::print("\00305> Done. ");
		  }
	  
	  
  }
  my $publicRSAkey =  Irssi::get_irssi_dir()."/fuckNSA/RSApublicKey";
    if ( !( -e $publicRSAkey) && (-e $privateRSAkey) ) {
	  Irssi::print("\00305> $publicRSAkey not found, setting to create new one\n");
	  Irssi::print("\00305> Getting your Public RSA key out from your Private one \n");
	  my $creatersapub;
	  eval{$creatersapub = `openssl pkey -in "$privateRSAkey" -pubout -out "$publicRSAkey" 2>>$errorlog`};
	  	  if ($@) {
			  Irssi::print("\00305> Something went wrong generating it, please retry later. ");
	  }else {
		  Irssi::print("\00305> Done. ");
		  }
	  
  }
  
  if ( !( -e $publicRSAkey) or !( -e $privateRSAkey) ) {
	  Irssi::print("\00304> SOMETHING WRONG GENERATING YOUR RSA KEYS. SHUTTING DOWN. ");
	  exit;
  }

  my $current;
  foreach(@conf) {
    $current = $_;
    $current =~ s/\n//g;
    if ($current =~ m/key/) {
      $current =~ s/.*\:[\ \t]*//;
      $key = $current;
      $gkey = $key;
    }
    if ($current =~ m/header/) {
      $current =~ s/.*\:[\s\t]*\{(.*).*/{$1/;
      $header = $current;
    }
    if ($current =~ m/wildcardserver/) {
      $current =~ s/.*\:[\ \t]*//;
      $enableWildcard = $current;
    }
  }
  Irssi::print("\00314- configuration file loaded\n");
  return 1;
}
loadconf;


my $kfile = Irssi::get_irssi_dir()."/fuckNSA/fuckNSA.keys";
my @keys;
$gkey=$key;
my $gparanoia=$paranoia;

sub loadkeys
{
  if ( -e "$kfile" ) {
    open (KEYF, "<$kfile");
    @keys = <KEYF>;
    close (KEYF);
  }
  Irssi::print("\00314- keys reloaded (Total:\00315 ". scalar(@keys) ."\00314)\n");
  return 1;
}
loadkeys;

sub loadkeys2
{
  if ( -e "$kfile" ) {
    open (KEYF, "<$kfile");
    @keys = <KEYF>;
    close (KEYF);
  }
  return 1;
}


sub getkey2
{
  my ($curserv, $curchan) = @_;

  my $gotkey=0;
  my $serv;
  my $chan;
  my $fkey;
  
  @key2use = ();

  foreach(@keys) {
    chomp;                                            
    my ($serv,$chan,$fnick,$fkey)=split /:/,$_,4; 
    if ( $curserv =~ /$serv/ and $curchan eq $chan ) {

      $gotkey=1;
      my $tuffy = $fnick . " " . $fkey;
      push(@key2use,$tuffy);

      if ($fnick eq "@") {
	   
	     @key2use = ();
	     $key2use[0]="@ " . $fkey;
         ## if there's a general key for the current channel, it
         ## will be used instead the individual keys registered 
         ## deleting the general key with just /delkey will re-enable the
         ## use of any pre-existing individual key again
         ## feel free to modify this policy for your team
	     return (@key2use);
	     
	  
	  }
    }
  }
  if (!$gotkey) {
    my $tuffy2 = "@ " . $gkey ;
    ## it will default to use the default key hardcoded here
    ## its not a good thing to keep at less you r only testing
    push(@key2use,$tuffy2);
  }
  return (@key2use) ;
}

sub getkey3
{
  my ($curserv, $curchan) = @_;

  my $gotkey=0;
  my $serv;
  my $chan;
  my $fkey;
  
  @key2use = ();

  foreach(@keys) {
    chomp;                                            
    my ($serv,$chan,$fnick,$fkey)=split /:/,$_,4; 
    if ( $curserv =~ /$serv/ and $curchan eq $chan ) {

      $gotkey=1;
      my $tuffy = $fnick . " " . $fkey;
      push(@key2use,$tuffy);

    }
  }
  if (!$gotkey) {
    my $tuffy2 = "@ " . $gkey ;
    push(@key2use,$tuffy2);
  }
  return (@key2use) ;
}


sub setkey2
{
  my (undef,$server, $channel) = @_;
  if (! $channel) { return 1; }
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  
  my @set2set = split(" ",$_[0]);

  my $fparanoia;
  my $nick2set;

  my $newchan=1;

  unless ($set2set[1]) {
	  $set2set[1] = "@"
  }

  $key = $set2set[0];
  $nick2set = $set2set[1];

  if($enableWildcard =~ /[Yy][Ee][Ss]/) {
      $curserv =~ s/(.*?)\./(.*?)\./;
    Irssi::print("\00314IRC server wildcards enabled\n");
  }
  ## k` you there?
  ## < k`> fapping now
  
    my $line="$curserv:$curchan:$nick2set:$key";

  open (KEYF, ">$kfile");
  foreach(@keys) {
    s/\n//g;
    if (/^$curserv\:$curchan\:$nick2set\:/) {
      print KEYF "$line\n";
      $newchan=0;
    } else {
      print KEYF "$_\n";
    }
  }
  if ($newchan) {
    print KEYF "$line\n";
  }
  close (KEYF);
  loadkeys2();
  if ($nick2set eq "@") {
  Irssi::active_win()->print("\00314key set to \00315$key\00314 for channel \00315$curchan");
  }else{
  
  Irssi::active_win()->print("\00314key set to \00315$key\00314 for nick: \00315$nick2set\00314 in channel \00315$curchan");
  }
  
  return 1 ;
}

sub setkey3
{
  my (undef,$server, $channel) = @_;
  if (! $channel) { return 1; }
  my $curchan = $channel;
  my $curserv = $server->{address};
  
  my @set2set = split(" ",$_[0]);

  my $fparanoia;
  my $nick2set;

  my $newchan=1;

  unless ($set2set[1]) {
	  $set2set[1] = "@"
  }

  $key = $set2set[0];
  $nick2set = $set2set[1];

  if($enableWildcard =~ /[Yy][Ee][Ss]/) {
      $curserv =~ s/(.*?)\./(.*?)\./;
    #Irssi::print("\00314IRC server wildcards enabled\n");
  }

    my $line="$curserv:$curchan:$nick2set:$key";

  open (KEYF, ">$kfile");
  foreach(@keys) {
    s/\n//g;
    if (/^$curserv\:$curchan\:$nick2set\:/) {
      print KEYF "$line\n";
      $newchan=0;
    } else {
      print KEYF "$_\n";
    }
  }
  if ($newchan) {
    print KEYF "$line\n";
  }
  close (KEYF);
  loadkeys2();

    if ($nick2set eq "@") {
  Irssi::active_win()->print("\00314key set to \00315$key\00314 for channel \00315$curchan");
  }else{
  
  Irssi::active_win()->print("\00314key set to \00315$key\00314 for nick: \00315$nick2set\00314 in channel \00315$curchan");
  }
  return 1 ;
}


sub delkey2
{
  my ($data, $server, $channel) = @_;
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my $nickd = $data;
  
  if (length($nickd) < 1) {
	  $nickd = "@";
  }

  my $serv;
  my $chan;
  my $nickf;

  open (KEYF, ">$kfile");
  foreach(@keys) {
    s/\n//g;
    ($serv,$chan,$nickf)=/^(.*?)\:(.*?)\:(.*?)\:/;
   unless ($curserv =~ /$serv/ and $curchan=~/^$chan$/ and $nickd=~/^$nickf$/) {
      print KEYF "$_\n";
    }
  }
  close (KEYF);
  if ( $nickd eq "@" ) {
	 Irssi::active_win()->print("\00314key for channel \00315$curchan\00314 deleted");
  }else{
     Irssi::active_win()->print("\00314key for channel \00315$curchan\00314 and user \00315$nickd\00314 deleted");
  }
  loadkeys2();
  ## if there was nothing to delete thou since the beginning it wont care about it anyway, you can improve this if you dont like it ##
  return 1 ;
}

sub delAllkeys
{
  my ($data, $server, $channel) = @_;
  my $curchan = $channel->{name};
  my $curserv = $server->{address};

  my $serv;
  my $chan;

  open (KEYF, ">$kfile");
  foreach(@keys) {
    s/\n//g;
    ($serv,$chan)=/^(.*?)\:(.*?)\:/;
   unless ($curserv =~ /$serv/ and $curchan=~/^$chan$/) {
      print KEYF "$_\n";
    }
  }
  close (KEYF);
  Irssi::active_win()->print("\00314All keys for channel \00315$curchan\00314 deleted");
  loadkeys2;
  return 1 ;
}

sub showkey2 {
  my (undef, $server, $channel) = @_;
  if (! $channel) { return 1; }
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  
  
  Irssi::active_win()->print("\00314current keys for this channel are : ");
  
  my @gotkeys = getkey3($curserv,$curchan);
  foreach (@gotkeys) {
	  my $k2s = $_;
	  $k2s =~ s/ / \| Key: /;
	  $k2s =~ s/^/Nick: /;
	  Irssi::active_win()->print("$k2s");
	  
  }

  return 1 ;
}

## what r u fapping to?
## < k`> tentacle hentai \:D/


sub enc2
{
  my ($curserv,$curchan,$in,$keyto) = @_;

  
  
  
  $cipher->{'passphrase'} = $keyto;

 ## IMPORTANT ##
 ## why using small hmackeys and small hmacs on convos?
 ## it would be enough to make difficult
 ## to forge messages on real time during a convo
 ## but easier to forge old messages exchanged, on the long run
 ## making old messages exchanged potentially fakes
 ## for the sake of deniability
 ## its a temporary decision, you can bring a better solution
 ## here

  my $msg_hash;

  my $tbout = $in;
  my $hmackey;
  
  eval{$hmackey = sha256_base64($keyto)};
  #Irssi::active_win()->print("$hmackey");
  $hmackey = substr($hmackey,0,8);
  
  if ( $debugging == 1 ) {
       Irssi::active_win()->print("hmackey " . "$hmackey");
   }
   
  $msg_hash = hmac_sha256_hex($tbout, $hmackey);
 

   my $cipheredtext = $cipher->encrypt($tbout);
   $cipheredtext = encode_base64($cipheredtext,"");

   
   $tbout = $cipheredtext;

 
   $msg_hash = substr($msg_hash,0,8);
   #Irssi::active_win()->print("hash " . "$msg_hash");
 

  #Irssi::active_win()->print("$tbout");
  return (length($tbout),$tbout,$msg_hash);

}



sub irclen2 {
	
	my ($curchan,$nick,$userhost) = @_;

  
  
  

  return (length($curchan) + length("PRIVMSG : ") + length($userhost) + 1 + length($nick) );
	
}



sub splittus {
	my ($server,$curchan,$in,$msg_hash,$funheader) = @_;
	

	

		my $encrypted_message = $in;
	my $len = length($encrypted_message);
	
	my $hleng = irclen2($curchan,$server->{nick},$server->{userhost});
	# you can fine tune this we rounded up too much just in case 
	my $rudux = (450 - $hleng) - length($msg_hash) - length($funheader) - 10;
	
	my $quantus = ceil($len / $rudux);
	
	
	my $i;
	my @out;

      
      my $basis="A".$rudux;
      
      @out = unpack("$basis" x $quantus,$encrypted_message);
            
 

	my @ready2go;

		my $renum=0;
		foreach(@out) {
			     $renum++;
				#Irssi::active_win()->print($funheader." ". $msg_hash . " " . $renum . " " . scalar(@out) . " " . $_ );
  		
          my $formattedencrypted = $funheader." ". $msg_hash . " " . $renum . " " . scalar(@out) . " " . $_  ;

          push(@ready2go,$formattedencrypted);
  	      

  
  
  }
	
	
	
	foreach(@ready2go) {
	$server->command("/^msg -$server->{tag} $curchan ".$_);
	            if ( $debugging == 1 ) {
				Irssi::active_win()->print("message sent: " . $_);
			}
    }
}

	

my (%current_message);



sub get_all_together {
	my @data;
	my $idx;
	my $compacted;
	my $hashmsg;
	my ($serv,$msg,$channel,$nick) = @_;
	my $server = $serv->{address};
				my @blockarray;

	  
	
    @data=split(" ",$msg);

    if ($data[0]=~ m/^([a-f0-9]*)$/i) {
		
	
	    if ( ($current_message{ $server}{$nick}{hash}) && ($data[0] eq $current_message{ $server}{$nick}{hash}) ) {
		
			
				 $idx=(int($data[1]) - 1);
				
				 
				 @blockarray = split("  ",$current_message{ $server}{$nick}{blocks}) if defined $current_message{ $server}{$nick}{blocks} ;
				 $blockarray[$idx] = $data[3];
				 
                 
				 $current_message{ $server}{$nick}{blocks} = join("  ",@blockarray);

			     if ( scalar(@blockarray) == int($current_message{ $server}{$nick}{totalblocks}) ) {
					 
					 $compacted = join("",@blockarray);
					 $hashmsg = $current_message{ $server}{$nick}{hash} ;
					 $current_message{ $server}{$nick}{blocks} = "";
				     return ($compacted,$hashmsg);
				 }

   }else {

	          
	          $current_message{ $server}{$nick}{hash} = $data[0] ; 
	          
			  $current_message{ $server}{$nick}{totalblocks} = $data[2];	           
				              
     
	            
				 $idx=(int($data[1]) - 1);
				 
				
				 
				 @blockarray = split("  ",$current_message{ $server}{$nick}{blocks}) if defined $current_message{ $server}{$nick}{blocks} ;
				 $blockarray[$idx] = $data[3];
				 
           
				 $current_message{ $server}{$nick}{blocks} = join("  ",@blockarray);
				 
		 
				
			     if ( scalar(@blockarray) == int($current_message{ $server}{$nick}{totalblocks}) ) {
					 
					 			
					 $compacted = join("",@blockarray);
					
					 $hashmsg = $current_message{ $server}{$nick}{hash} ;
					 $current_message{ $server}{$nick}{blocks} = "";
				     return ($compacted,$hashmsg);
				 }
				 
			 }
	   
	   
	   }
       
#      print Dumper(%current_message);
     
    
	
}



sub fuckit
{
  my ($data, $server, $channel) = @_;
  if (! $channel) { return 1;}
  my $in = $data ;
  my $nick = $server->{nick};
  my $curchan = $channel->{name};
  my $curserv = $server->{address};

  
  my @gotkeys = getkey2($curserv,$curchan);

  
  foreach (@gotkeys) {
	  
	   my @target =split(" ",$_);
	   my $tnick = $target[0];
	   my $theader = "{fuckNSA_$tnick?";
	   my $keyto = $target[1];
	  
	  

           if ( $tnick eq "@" ) {
			    my ($len,$encrypted_message,$msg_hash) = enc2($curserv,$curchan,$in,$keyto);
                splittus($server,$curchan,$encrypted_message,$msg_hash,$theader);
		   }else{
           
           
           my $nickexists = $channel->nick_find_mask($tnick);
           
           if ( ($nickexists) and ($nickexists->{nick} eq $tnick)) {
	  
	    my ($len,$encrypted_message,$msg_hash) = enc2($curserv,$curchan,$in,$keyto);
        splittus($server,$curchan,$encrypted_message,$msg_hash,$theader);
          }
	  }
  }
  

 
  $server->print($channel->{name}, "\00310<$nick|{\00305encrypted\00310}> \00311$in",MSGLEVEL_CLIENTCRAP);



  return 1 ;
}

sub infoline {
	 my ($server, $data, $nick, $address) = @_;
	 

      my ($channel,$msg,$data2);
      $data2 = $data;
      
	 ($channel, $msg) = $data =~ /^(\S*)\s:(.*)/;
	 	
     my $msgnick = $server->{nick};
    my $curchan = $channel;
    
    
    if ($msgnick eq $channel)
   {
       $curchan = $channel = $nick;
    }
    
    
	 my @data=split(" ",$msg);
	 $data[0] =~ s/\?//;
	 
	      if ( $debugging == 1 ) {
		        if ( ($data[0] =~ /^{fuckNSA/) or ($data[0] =~ /^{fNSA/) ) {
				Irssi::active_win()->print("message received: $msg");
			   }
			} 

     if ($data[0] =~ /^$header/) {
             	

            if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {

              infoline2($server,$data2,$nick,$address);
		  }else{
			  Irssi::signal_stop();
		  }
        
        }     
	    if ($data[0]=~ m/^$DHinit$/i) {
	
			answer_init_DH($server,$msg,$nick,$channel);
						

		}
	    if ($data[0]=~ m/^$DHinit2/i) {
	          if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {
			          
			          answer_init_DH($server,$msg,$nick,$channel);
		  }else{
			  Irssi::signal_stop();
		  }
		}
	 
		       if ($data[0]=~ m/^$answDHinit/i) {
                     if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {
			         
			           ask_DH_pub($server,$msg,$nick,$channel);
					
		  }else{
			  Irssi::signal_stop();
		  }

		}
		 
            if ($data[0]=~ m/^$DHgimmePubheader/i) {
               if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {

                       asked2DH_pub($server,$msg,$nick,$channel);
             
		  }else{
			  Irssi::signal_stop();
		  }
        }
	
            if ($data[0]=~ m/^$DHgimmeFiveBroheader/i) {
                if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {
             
                       receiving_DH_pubcombo($server,$msg,$nick,$channel);
                       
		  }else{
			  Irssi::signal_stop();
		  }
        }
   
           if ($data[0]=~ m/^$DHstuffIncomingheader/i) {
                 if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {
            
                       getting_DH_xtracombo($server,$msg,$nick,$channel);
             
		  }else{
			  Irssi::signal_stop();
		  }
        }
       
          if ($data[0]=~ m/^$DHgimmetheCandy/i) {
                   if ( ($data[0] =~ /$msgnick$/) or ($data[0] =~ /_@/) ) {
                           
                        I_cant_get_Satisfaction($server,$msg,$nick,$channel);
                         
		  }else{
			  Irssi::signal_stop();
		  }
        }
        
       
}



sub infoline2
{
  my ($server, $data, $nick, $address) = @_;

  my ($channel,$text,$msgline,$msgnick,$curchan,$curserv);

  if ( ! defined($address) ) ## dcc chat support from original blowjob. enable it if u want it
  {
    #  $msgline = $data;
  #  $curserv = $server->{server}->{address};
  #  $channel = $curchan = "=".$nick;
  #  $msgnick = $nick;
   # $server  = $server->{server};
   return 1;
  } else 
  {
    ($channel, $text) = $data =~ /^(\S*)\s:(.*)/;
    $msgline = $text;
    $msgnick = $server->{nick};
    $curchan = $channel;
    $curserv = $server->{address};
  }

  if ($msgline =~ m/^$header/) {
	   
    my $out = $msgline;
    
       
    $out =~ s/\0030[0-9]//g;
    $out =~ s/\?//;
    $out =~ s/^$header\s*(.*)/$1/;
    $out =~ s/^$msgnick\s*(.*)/$1/;
    $out =~ s/^@\s*(.*)/$1/;
    
       
    if ($msgnick eq $channel)
    {
       $curchan = $channel = $nick;
    }

 
    my $hashmsg;
    ($out,$hashmsg) = get_all_together($server,$out,$curchan,$nick);
     if(!$out) {
		        Irssi::signal_stop();
                return;
		 }
		 
		 if(! length($out))
    {
       
       

       Irssi::signal_stop();
       return;
    }

my @keys2use = getkey2($curserv,$curchan);
my $goOnbitch = 0;
my $keyto;
my $hmackey;

foreach (@keys2use) {
	   my @sender =split(" ",$_);
	   my $tnick = $sender[0];
	   my $keyto = $sender[1];
	if ( ($nick eq $tnick) or ($tnick eq "@") ) {
	
	    $cipher->{'passphrase'} = $keyto;
	     
    eval{$hmackey = sha256_base64($keyto)};
	    $goOnbitch = 1 ;
	
	}else{
		
	
		}
	
	
	
}
 if ( $goOnbitch != 1 ) {
   return;
	 }
 
 
         #Irssi::active_win()->print("starting to decrypt");


   my $msg_hash;

  

  $hmackey = substr($hmackey,0,8);
  
             if ( $debugging == 1 ) {
				Irssi::active_win()->print("hmackey " . "$hmackey");
			}
  #


      
 

        $out = decode_base64($out);
     
 
    my $decipheredtext = $cipher->decrypt($out);
 
    
    $out = $decipheredtext;
    
    
      

    eval {$msg_hash=hmac_sha256_hex($out,$hmackey)};
 
       

   $msg_hash = substr($msg_hash,0,8);   
     

 

    if(length($out))
    {
       $server->print($channel, "\00310<$nick|{\00305decrypted\00310}> \00311$out", MSGLEVEL_CLIENTCRAP);
       Irssi::signal_stop();
       
       if ($msg_hash eq $hashmsg ) {
		   if ( $debugging == 1 ) {
				Irssi::active_win()->print("Hashes for the last message match! things look fine..." . "$msg_hash" . " == " . "$hashmsg");
			}
		   #
	   }else{
		   Irssi::active_win()->print("Hashes for the last message DONT match! something is fuckin bad..." . "$msg_hash" . " != " . "$hashmsg");
		   }
    }
    return 1;

  }
  return 0 ;
}

sub dccinfoline   ## we dont like dcc too much but we left it from original blowjob.pl
{
  my ($server, $data) = @_;
  infoline($server,$data,$server->{nick},undef);
}

my (%permchans);
sub perm
{
   my ($data, $server, $channel) = @_;
   if (! $channel) { return 1; }
   my $curchan = $channel->{name};
   my $curserv = $server->{address};
  
   if ( exists($permchans{$curserv}{$curchan}) && $permchans{$curserv}{$curchan} == 1) {
    delete $permchans{$curserv}{$curchan};
    Irssi::active_win()->print("\00314not crypting to \00315$curchan\00314 on \00315$curserv\00314 anymore");
  } else {
    $permchans{$curserv}{$curchan} = 1;
    Irssi::active_win()->print("\00314crypting to \00315$curchan on \00315$curserv");
  }
  return 1;
}
sub myline
{
  my ($data, $server, $channel) = @_;
  if (! $channel) { return 1; }
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my $line = shift;
  chomp($line);
  if (length($line) == 0)
  {
    return;
  }
  my $gotchan = 0;
  foreach(@keys) {
    s/\n//g;
    my ($serv,$chan,undef,undef)=split /:/;
    if ( ($curserv =~ /$serv/ && $curchan =~ /^$chan$/ && exists($permchans{$curserv}{$curchan}) && $permchans{$curserv}{$curchan} == 1) || (exists($permchans{$curserv}{$curchan}) && $permchans{$curserv}{$curchan} == 1))
    {
      $gotchan = 1;
    }
  }
  if ($gotchan)
  {

    fuckit($line,$server,$channel);
    Irssi::signal_stop();
    return 1;
  }
}

sub reloadconf
{
  loadconf;
  loadkeys;
}

sub set_debug {
	
	if ( $debugging == 0) {
		$debugging = 1;
		Irssi::active_win()->print("\00304Debugging Mode is ON");
	}else{
		$debugging = 0;
		Irssi::active_win()->print("\00304Debugging Mode is OFF");
	}
	
}
sub help
{
  Irssi::active_win()->print("\00314[\00303fuck\00309NSA\00314]\00315 script :\n");
  Irssi::active_win()->print("\00315/gimmekeys <nick> [<nicks>]   :\00314 start a Key Exchange process to ");
  Irssi::active_win()->print("\00315                               \00314 get a shared key with the given nick or nicks\n") ;
  Irssi::active_win()->print("\00315/everyonegimmekeys            :\00314 ask everyone to start a Key Exchange process ");
  Irssi::active_win()->print("\00315                               \00314 to get a shared key (potentially annoying)\n");
  Irssi::active_win()->print("\00315/setkey <newkey> [<nick>]     :\00314 new key for current channel, either a ");
  Irssi::active_win()->print("\00315                               \00314 general key or individual key for given nick\n") ;
  Irssi::active_win()->print("\00315/showkey                      :\00314 show keys for current channel. the @ symbol ");
  Irssi::active_win()->print("\00315                               \00314 means it is a general key for the whole channel.\n") ;
  Irssi::active_win()->print("\00315/delkey [<nick>]              :\00314 delete the general key or individual keys");
  Irssi::active_win()->print("\00315                               \00314 for current channel \n");
  Irssi::active_win()->print("\00315/delallkeys                   :\00314 delete ALL the keys available for the current channel \n");
  Irssi::active_win()->print("\00315/enc <message>                :\00314 send encrypted message\n") ;
  Irssi::active_win()->print("\00315/perm                         :\00314 toggle between permanent enabling "); 
  Irssi::active_win()->print("\00315                               \00314 encrypting or not to the current channel") ;
  Irssi::active_win()->print("\00315/kalc <string>                :\00314 use KeithAlexanderLovesCocks to derive a ");
  Irssi::active_win()->print("\00315                               \00314 passphrase from a given string (pl0x > 6 chars long)") ;
  Irssi::active_win()->print("\00315/lurkmoar                     :\00314 enable or disable extra verbosity\n") ;
  Irssi::active_win()->print("\00315/reloadfucknsaconf            :\00314 reload fuckNSA.conf\n") ;
  Irssi::active_win()->print("\n\n");
  Irssi::active_win()->print("\00304BASIC INSTRUCTION: TO START AN OTR ENCRYPTED CONVERSATION type: /gimmekeys <nick> [<othernicks>]") ;
  Irssi::active_win()->print("\00304example: /gimmekeys kayla     or   /gimmekeys kayla sharpie glomex   (for multiple nicks)") ;
  Irssi::active_win()->print("\00304you can also do: /everyonegimmekeys  ");   
  Irssi::active_win()->print("\00304(but beware this could overflood the whole channel if many ppl are there)") ;
  Irssi::active_win()->print("\00304tip to avoid flooding channels: ask some keys on private queries and then use them to set channel keys") ;
  Irssi::active_win()->print("\00304encryption can be enabled or disabled if sensitive info will be exchanged or not") ;
  Irssi::active_win()->print("\00304ATTENTION: if a general key has been set for a given channel, this will be used instead individual ones");
  Irssi::active_win()->print("\00304It's easy to customise the current code to adapt it to different situations if it is needed");

  return 1 ;
}

Irssi::print("fuckNSA script $VERSION") ;
Irssi::print("\n\00314[\00309fuck\00303NSA\00314] v$VERSION\00315 script loaded\n\n");
Irssi::print("\00314- type \00315/fucknsahelp\00314 for help and options\n") ;
Irssi::print("\00314- generic key is         : \00315$key\n") ;
Irssi::print("\n\00314* please read script itself for documentation\n");
Irssi::print("\00304BASIC INSTRUCTION: TO START AN OTR ENCRYPTED CONVERSATION type: /gimmekeys <nick> [<othernicks>]") ;
Irssi::print("\00304example: /gimmekeys kayla     or   /gimmekeys kayla sharpie glomex   (for multiple nicks)") ;

Irssi::signal_add("event privmsg","infoline") ;
#Irssi::signal_add("dcc chat message","dccinfoline");  ## enable it if u want it. 
Irssi::command_bind("fucknsahelp","help") ;
Irssi::command_bind("setkey","setkey2") ;
Irssi::command_bind("delkey","delkey2");
Irssi::command_bind("enc","fuckit") ;
Irssi::command_bind("showkey","showkey2") ;
Irssi::command_bind("perm","perm") ;
Irssi::command_bind("bconf","reloadconf") ;
Irssi::signal_add("send text","myline") ;
Irssi::command_bind("everyonegimmekeys","init_DH") ;
Irssi::command_bind("gimmekeys","init_DH_nick") ;
Irssi::command_bind("kalc","KALC_me") ;
Irssi::command_bind("lurkmoar","set_debug") ;
Irssi::command_bind("delallkeys","delAllkeys") ;

sub hashing_shits {
	
	my @dat = @_;
	
	my $dat = join("@",@_);
	
	$dat = sha256_hex($dat);
	
	$dat = substr($dat,0,16);
	
	return $dat;
	
	
	
}

sub KALC_me {
	
	my ($data, $server, $channel) = @_;
	if (length($data) < 6 ) {
		Irssi::active_win()->print("Don't be such a lazy cunt, gimme at least a 6 chars long string");
	}else{
	my($runforrestrun,$adrianchenstutu,$sabutraitor) = KeithAlexanderLovesCocks($data);
	
	Irssi::active_win()->print("\00314KeithAlexanderLovesCocks said: " . "\00315".$runforrestrun );
    }
}



my (%tempkey);
my (%controlbit);

sub init_DH_nick {
	my ($data, $server, $channel) = @_;
	my $curchan = $channel->{name};
	
   if ( length($data) > 0 ) {
   my @g2annoy = split(" ",$data);

    foreach (@g2annoy) {
    if ( length($_) > 0 ) {
		my $gk = "{fuckNSA-ANNCD-" . $_ . "?"; 
		$server->command("MSG $curchan " . $gk);
	}else{
			Irssi::active_win()->print("Usage: /gimmekeys <nick>");

	}
  }
  }else{
	  			Irssi::active_win()->print("Usage: /gimmekeys <nick>");
  }
}

sub init_DH {
	my ($data, $server, $channel) = @_;
	my $curchan = $channel->{name};
   
    $server->command("MSG $curchan " . $DHinit);

}

sub answer_init_DH { 
	my ($server, $msg, $nick, $channel) = @_;


     my $newheader = $answDHinit . $nick . "?";
     	$server->command("MSG $channel " . $newheader);


}

sub ask_DH_pub {
	
	my ($server, $msg, $nick, $channel) = @_;

	
	    my $servaddr = $server->{address};
	    
	    my $prefixf = hashing_shits($nick,$servaddr);
	
		 my $dhparamfile = $folder."dh-4096.pem";
		 my $dhprivkey = $convofolder . $prefixf . "-dhprivatekey";
		 my $dhpubkey = $convofolder . $prefixf . "-dhpubkey";
		   
	 
	
  

    my $ttkey;
	$ttkey = Crypt::CBC->random_bytes('128');
    $ttkey = sha512_base64($ttkey,"");
    $ttkey=substr($ttkey,0,64);
    $tempkey{ $servaddr}{$nick}{'tempkey'} = $ttkey;
	

	
	my $gennewkeys;
	my $genpubkeys;
	eval{$gennewkeys=`openssl genpkey -paramfile "$dhparamfile" -out "$dhprivkey" 2>>$errorlog`};
		  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong generating your dh private key, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> your DH private key created. ");
		  eval{$genpubkeys=`openssl pkey -in "$dhprivkey" -pubout -out "$dhpubkey" 2>>$errorlog`};
		  	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong generating it, please retry later. ");

	          }else {
		       Irssi::active_win()->print("\00305> Done. your DH public key created ");
		    }
		  
		  }
 
 if ( !( -e $dhprivkey) and !( -e $dhpubkey) ) {
	 
	 Irssi::active_win()->print("\00305> The Process of creation of your pair of DH private and public keys has failed, retry later. ");
	 return 1;
	 
 }
 
 $cipher->{'passphrase'} = $ttkey;
 

    my $minepub;
    open(my $fh, '<', $dhpubkey) or die "cannot open file $dhpubkey";
    {
        local $/;
        $minepub = <$fh>;
    }
    close($fh);
  
 
    
    my $encminepub = $cipher->encrypt($minepub);
    $encminepub = encode_base64($encminepub,"");


	my $hmk = substr((sha256_base64($ttkey)),0,24);
	my $pubkeyhash = hmac_sha256_hex($minepub,$hmk);
	
		
	$pubkeyhash=substr($pubkeyhash,0,30);


	    $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'Cool';

      Irssi::active_win()->print("Please wait for the key exchange process to complete ");

      my $newheader = $DHgimmePubheader . $nick . "?";

 	 splittus($server,$channel,$encminepub,$pubkeyhash,$newheader);

	
        }

my (%curKE1);     
my (%curKE1hash);
        
sub asked2DH_pub {
	 my ($server, $msg, $nick, $channel) = @_;
	  
	 	 my $servaddr = $server->{address};
	 	 
	 	 my $prefixf = hashing_shits($nick,$servaddr);

	  my $dhparamfile = $folder."dh-4096.pem";
	  my $dhprivkey = $convofolder . $prefixf . "-dhprivatekey";
	  my $dhpubkey = $convofolder . $prefixf . "-dhpubkey";
	

	 my @data;
	 @data=split(" ",$msg);
	 shift @data;


	 my $out;
	     my $hashmsg;
    ($out,$hashmsg) = get_all_together($server,join(" ",@data),$channel,$nick);
     if(!$out) {
		        Irssi::signal_stop();
                return;
		 }
		 
		 if(! length($out))
    {
       
       

       Irssi::signal_stop();
       return;
    }
	


	$out=decode_base64($out);

	 
	 $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'Cool';
      Irssi::active_win()->print("Please wait for the key exchange process to complete ");


	 $curKE1hash{ $servaddr}{$nick}{'hashKE'}=$hashmsg;
	 $curKE1{ $servaddr}{$nick}{'encryptedpeerkey'}=$out;
	 
	my $gennewkeys;
	my $generationpubkey;
	eval{$gennewkeys=`openssl genpkey -paramfile "$dhparamfile" -out "$dhprivkey" 2>>$errorlog` };
		  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong generating the DH private key, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> DH private key Done. ");
		  	eval{$generationpubkey=`openssl pkey -in "$dhprivkey" -pubout -out "$dhpubkey" 2>>$errorlog`};

	         if ($@) {
		  	    Irssi::active_win()->print("\00305> Something went wrong generating it, please retry later. ");

	         }else {
		        Irssi::active_win()->print("\00305> Done. DH public key created.");
		      }
		  
		  
		  }
		  
	 if ( !( -e $dhprivkey) and !( -e $dhpubkey) ) {
	 
	 Irssi::active_win()->print("\00305> The Process of creation of your pair of DH private and public keys has failed, retry later. ");
	 return 1;
	 
 }

	
	
	
	my $genpubkey;
    open(my $fh, '<', $dhpubkey) or die "cannot open file $dhpubkey";
    {
        local $/;
        $genpubkey = <$fh>;
    }
    close($fh);
	
	
	
	
	my $pubkeyhash = sha256_hex($genpubkey);	
	$pubkeyhash = substr($pubkeyhash,0,32);
	$genpubkey = compress($genpubkey);
	$genpubkey = encode_base64($genpubkey,"");


     my $newheader = $DHgimmeFiveBroheader . $nick . "?";
 	 splittus($server,$channel,$genpubkey,$pubkeyhash,$newheader);
	
	  Irssi::signal_stop();
} 
        
sub receiving_DH_pubcombo {
         my ($server, $msg, $nick, $channel) = @_;
         
         	 my $servaddr = $server->{address};
         	 
         	 my $prefixf = hashing_shits($nick,$servaddr);

         
         my $dhparamfile = $folder."dh-4096.pem";
		 my $dhprivkey = $convofolder . $prefixf . "-dhprivatekey";
		 my $dhpubkey = $convofolder . $prefixf . "-dhpubkey";
		 my $peerkey = $convofolder . $prefixf . "-dhpeerkey";
		 
		 my $RSAprivKey = $folder."RSAprivateKey";
	     my $RSApubKey = $folder."RSApublicKey";
			 	 
	     
	     my $MACcollecFile = $convofolder. $prefixf . "-MACcollec";
	     
	     	

			 	 
		   	 my @data;
		   	 @data=split(" ",$msg);
	 shift @data;
	 
	 my $out;
             	     my $hashmsg;

        ($out,$hashmsg) = get_all_together($server,join(" ",@data),$channel,$nick);

     if(!$out) {
		        Irssi::signal_stop();
                return;
		 }
		 
		 if(! length($out))
    {
       
       

       Irssi::signal_stop();
       return;
    }
         

 
    $out = decode_base64($out);
    $out = uncompress($out);
    
                  
     my $checkhashpubpeer = sha256_hex($out);
     $checkhashpubpeer = substr($checkhashpubpeer,0,32);
     
    if ( $checkhashpubpeer eq $hashmsg) {
		     
		     
		    $controlbit{ $servaddr}{$nick}{'checkpoints'} = "OK. Hash for initially asked peer's DH public key looks fine. \n";
			

	}else{
        $controlbit{ $servaddr}{$nick}{'checkpoints'} = "NOT GOOD. Hash for initially asked peer's DH public key DOESN'T LOOK GOOD. \n";
        $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';

	}

    open(PEERKEY,">$peerkey");
    print PEERKEY "$out";
    close(PEERKEY);
    
    my $derivesecret;
    eval{$derivesecret=`openssl pkeyutl -derive -inkey "$dhprivkey" -peerkey "$peerkey" 2>>$errorlog` };
    	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong derivating it, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> Shared Secret Derivation Done. ");
		  }
    if ( !($derivesecret) or (length($derivesecret) < 128)) {
		Irssi::active_win()->print("\00304### ATTENTION ###");
		Irssi::active_win()->print("\00305> SOMETHING WENT TOTALLY WRONG WITH THE SHARED SECRET DERIVATION STEP. CHECK IF YOU ARE SHARING THE SAME VALID PARAMETERS");
		Irssi::active_win()->print("\00304### key exchange process aborted ###");	
		return 1;
	}
    
    $derivesecret=unpack("H*",$derivesecret);
    
    
    
      Irssi::signal_stop();
    my $understring = " ";
    
    
    my $candidatesharedsecret1;
    my $candidatesharedsecret2;
    my $candidatesharedsecret3;
    
    ($candidatesharedsecret1,$candidatesharedsecret2,$candidatesharedsecret3) = KeithAlexanderLovesCocks($derivesecret);

    
    $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecret'} = $candidatesharedsecret1;
    $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecretFile'} = hmac_sha512_base64($candidatesharedsecret1,substr($derivesecret,13,37));

    
            if ( $debugging == 1 ) {
				Irssi::active_win()->print("Derived Shared Secret: $derivesecret");
			}
   
    $understring = substr($candidatesharedsecret3,0,16);
    my $SymmKey;
 
    $SymmKey = hmac_sha256_base64($derivesecret,$understring);
    $SymmKey=substr($SymmKey,0,64);
    
 
    $understring = substr($candidatesharedsecret3,16,32);
    my $SymmKeyBis;

    $SymmKeyBis = hmac_sha256_base64($derivesecret,$understring);
    $SymmKeyBis=substr($SymmKeyBis,0,64);
     
  
    $understring = substr($candidatesharedsecret2,0,16);
 
    my $firstHMACkey = hmac_sha256_base64($derivesecret,$understring);
    $firstHMACkey=substr($firstHMACkey,0,32);
      
   
    $understring = substr($candidatesharedsecret2,16,32);
 
    my $secondHMACkey = hmac_sha256_base64($derivesecret,$understring);
    $secondHMACkey=substr($secondHMACkey,0,40);

    
    $understring = substr($candidatesharedsecret2,32,48);
 
    my $firstHMACkeyBis = hmac_sha256_base64($derivesecret,$understring);
    $firstHMACkeyBis=substr($firstHMACkeyBis,0,32);
         
   
    $understring = substr($candidatesharedsecret2,48,64);
  
    my $secondHMACkeyBis = hmac_sha256_base64($derivesecret,$understring);
    $secondHMACkeyBis=substr($secondHMACkeyBis,0,40);
   
    
    $AKE{ $servaddr}{$nick}{'stuff'}{'SymmKey'} = $SymmKey;

    $AKE{ $servaddr}{$nick}{'stuff'}{'SymmKeyBis'} = $SymmKeyBis;
    
    $AKE{ $servaddr}{$nick}{'stuff'}{'firstHMACkey'} = $firstHMACkey;

    $AKE{ $servaddr}{$nick}{'stuff'}{'secondHMACkey'} = $secondHMACkey;

    $AKE{ $servaddr}{$nick}{'stuff'}{'firstHMACkeyBis'} = $firstHMACkeyBis;

    $AKE{ $servaddr}{$nick}{'stuff'}{'secondHMACkeyBis'} = $secondHMACkeyBis;

    
    my $rsapub;
    my $dhpub;
    my $dhpeerpub;
    
    if ( -e "$RSApubKey" ) {
    open(my $fha, '<', $RSApubKey) or die "cannot open file $RSApubKey";
    {
        local $/;
        $rsapub = <$fha>;
    }
    close($fha);
  }
        if ( -e "$dhpubkey" ) {
    open(my $fhb, '<', $dhpubkey) or die "cannot open file $dhpubkey";
    {
        local $/;
        $dhpub = <$fhb>;
    }
    close($fhb);
  }
      if ( -e "$peerkey" ) {
    open(my $fhc, '<', $peerkey) or die "cannot open file $peerkey";
    {
        local $/;
        $dhpeerpub = <$fhc>;
    }
    close($fhc);
  }
    
    my @MACss;
    
 
    $MACss[0] = hmac_sha256_hex($dhpub,$firstHMACkey);
    $MACss[0]=substr($MACss[0],0,63);
 
    $MACss[1] = hmac_sha256_hex($dhpeerpub,$firstHMACkey);
    $MACss[1]=substr($MACss[1],0,63);
   
    $MACss[2] = hmac_sha256_hex($rsapub,$firstHMACkey);
    $MACss[2]=substr($MACss[2],0,63);
    
    
    $rsapub=compress($rsapub);
    
    $rsapub = encode_base64($rsapub,"");
   
    
    my $MACcollec=join(" ",@MACss);
    $MACcollec=unpack("H*",$MACcollec);
    

    open(MACSEND,">$MACcollecFile");
    print MACSEND "$MACcollec";
    close(MACSEND);
    
    
    my $signedMACcollec;
    eval{$signedMACcollec=`openssl rsautl -sign -inkey "$RSAprivKey" -in "$MACcollecFile" 2>>$errorlog`};
    	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong generating it, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> Signature Done. ");
		  }

   if ( !($signedMACcollec) or (length($signedMACcollec) < 32)) {
	   Irssi::active_win()->print("\00304> Signature Failed. ABORTING KEY EXCHANGE. check errorlog");
	   return 1;
   }
    
    $signedMACcollec = encode_base64($signedMACcollec,"");
    
    my $pack2send= $rsapub . " " . $signedMACcollec ;
    $pack2send=compress($pack2send);
   
    $pack2send = encode_base64($pack2send,"");

 
     my $thehashpack = hmac_sha256_hex($pack2send,$secondHMACkey);
    
    $thehashpack=substr($thehashpack,0,40);   
    
    
    $cipher->{'passphrase'} = $SymmKey;
    $pack2send = $cipher->encrypt($pack2send);
    $pack2send = encode_base64($pack2send,"");
    
    
    my $final = $tempkey{ $servaddr}{$nick}{'tempkey'} . " " . $pack2send;
    $final=compress($final);
  
  $final = encode_base64($final,"");
    
    
     my $newheader = $DHstuffIncomingheader . $nick . "?";
 	 splittus($server,$channel,$final,$thehashpack,$newheader);
    
             
   }
        
sub getting_DH_xtracombo {
	my ($server, $msg, $nick, $channel) = @_;
	
	     		 my $servaddr = $server->{address};	
	     		 my $prefixf = hashing_shits($nick,$servaddr);

	     my $dhparamfile = $folder."dh-4096.pem";
	     
		 my $dhprivkey = $convofolder . $prefixf . "-dhprivatekey";
		 my $dhpubkey = $convofolder . $prefixf . "-dhpubkey";
		 my $peerkey = $convofolder . $prefixf . "-dhpeerkey";
		 
		 my $RSAprivKey = $folder."RSAprivateKey";
	     my $RSApubKey = $folder."RSApublicKey";
	     
	     
	     my $peerPUBRSAkey = $friendsfolder . $prefixf . "-peerRSApublicKey";
	     
	     my $signedMAC = $convofolder . $prefixf . "-signedMACs";
	     
	     my $MACcollecFile = $convofolder . $prefixf . "-MACcollec";

	     my $peerRSAfingerprintHistory = $friendsfolder . $prefixf . "-peerRSAfingerprintsHistory";

			 	 
		   	 my @data;
		   	 @data=split(" ",$msg);
	 shift @data;
	 
	 my $out;
     my $hashmsg;
             	    
        ($out,$hashmsg) = get_all_together($server,join(" ",@data),$channel,$nick);

     if(!$out) {
		        Irssi::signal_stop();
                return;
		 }
		 
		 if(! length($out))
    {
       
       

       Irssi::signal_stop();
       return;
    }
        
                  
             
             $out=decode_base64($out);  
             $out=uncompress($out);
                         

	Irssi::signal_stop();
	my @shits=split(" ",$out);
  
	 
	 my $File = $curKE1{ $servaddr}{$nick}{'encryptedpeerkey'};
	   
	my $recoverpeerkey;

	
	$cipher->{'passphrase'} = $shits[0];
	$recoverpeerkey = $cipher->decrypt($File);
	

     my $otherpub;


    open (KEYF, ">$peerkey");
    print KEYF $recoverpeerkey;
    close (KEYF);

  
    my $hmk = substr((sha256_base64($shits[0])),0,24);
    
    my $checkpeerkeyhash = hmac_sha256_hex($recoverpeerkey,$hmk);
    
	
	$checkpeerkeyhash=substr($checkpeerkeyhash,0,30);
	
	if ( $curKE1hash{ $servaddr}{$nick}{'hashKE'} eq $checkpeerkeyhash) {
		
		$controlbit{ $servaddr}{$nick}{'checkpoints'} = "OK. Hash for decrypted peer's DH public key looks fine. \n";


	}else{
		$controlbit{ $servaddr}{$nick}{'checkpoints'} = "NOT GOOD. Hash for decrypted peer's DH public key DOESN'T LOOK GOOD. \n";
        $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
	}
	
	
	
	    open(my $fh, '<', $peerkey) or die "cannot open file $peerkey";
    {
        local $/;
        $otherpub = <$fh>;
    }
    close($fh);

	
	   my $derivesecret;
	   eval{$derivesecret=`openssl pkeyutl -derive -inkey "$dhprivkey" -peerkey "$peerkey" 2>>$errorlog` };
	   	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong derivating it, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> Shared Secret Derivation Done.");
		  }
		  
	       if ( !($derivesecret) or (length($derivesecret) < 128)) {
		Irssi::active_win()->print("\00304### ATTENTION ###");
		Irssi::active_win()->print("\00305> SOMETHING WENT TOTALLY WRONG WITH THE SHARED SECRET DERIVATION STEP. CHECK IF YOU ARE SHARING THE SAME VALID PARAMETERS");
		Irssi::active_win()->print("\00304### key exchange process aborted ###");	
		return 1;
	}
    
    
    $derivesecret=unpack("H*",$derivesecret);
   
    
      Irssi::signal_stop();
      
      
     my $understring = " ";
     
   
    my $candidatesharedsecret1bis;
    my $candidatesharedsecret2bis;
    my $candidatesharedsecret3bis;
    
    ($candidatesharedsecret1bis,$candidatesharedsecret2bis,$candidatesharedsecret3bis) = KeithAlexanderLovesCocks($derivesecret);
  
    $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecret'} = $candidatesharedsecret1bis;
    $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecretFile'} = hmac_sha512_base64($candidatesharedsecret1bis,substr($derivesecret,13,37));
    
                if ( $debugging == 1 ) {
				Irssi::active_win()->print("Derived Shared Secret: $derivesecret");
			}
  
    $understring = substr($candidatesharedsecret3bis,0,16);
    my $SymmKey;

    $SymmKey = hmac_sha256_base64($derivesecret,$understring);
    $SymmKey=substr($SymmKey,0,64);
      

    $understring = substr($candidatesharedsecret3bis,16,32);
    my $SymmKeyBis;

    $SymmKeyBis = hmac_sha256_base64($derivesecret,$understring);
    $SymmKeyBis=substr($SymmKeyBis,0,64);
  
   
    $understring = substr($candidatesharedsecret2bis,0,16);
 
    my $firstHMACkey = hmac_sha256_base64($derivesecret,$understring);
    $firstHMACkey=substr($firstHMACkey,0,32);
    
    
    $understring = substr($candidatesharedsecret2bis,16,32);
 
    my $secondHMACkey = hmac_sha256_base64($derivesecret,$understring);
    $secondHMACkey=substr($secondHMACkey,0,40);
    
  
    $understring = substr($candidatesharedsecret2bis,32,48);

    my $firstHMACkeyBis = hmac_sha256_base64($derivesecret,$understring);
    $firstHMACkeyBis=substr($firstHMACkeyBis,0,32);
         
   
   $understring = substr($candidatesharedsecret2bis,48,64);

    my $secondHMACkeyBis = hmac_sha256_base64($derivesecret,$understring);
    $secondHMACkeyBis=substr($secondHMACkeyBis,0,40);
   
    

    $AKE{ $servaddr}{$nick}{'stuff'}{'SymmKey'} = $SymmKey;

    $AKE{ $servaddr}{$nick}{'stuff'}{'SymmKeyBis'} = $SymmKeyBis;
    
    $AKE{ $servaddr}{$nick}{'stuff'}{'firstHMACkey'} = $firstHMACkey;

    $AKE{ $servaddr}{$nick}{'stuff'}{'secondHMACkey'} = $secondHMACkey;

    $AKE{ $servaddr}{$nick}{'stuff'}{'firstHMACkeyBis'} = $firstHMACkeyBis;

    $AKE{ $servaddr}{$nick}{'stuff'}{'secondHMACkeyBis'} = $secondHMACkeyBis;
 
   
    
    my $receivedpack=$shits[1];
   
    
    $cipher->{'passphrase'} = $SymmKey;
    $receivedpack = decode_base64($receivedpack);
    $receivedpack = $cipher->decrypt($receivedpack);
       
    
 
    my $recvhashpack = hmac_sha256_hex($receivedpack,$secondHMACkey);

    $recvhashpack=substr($recvhashpack,0,40);
          
    
    	if ( $recvhashpack eq $hashmsg) {
		
		
		$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. Hash for decrypted package with peer's RSA public keys and signed MACs looks fine. \n";
	

	}else{
				$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. Hash for decrypted package with peer's RSA public keys and signed MACs DOESN'T LOOK GOOD. \n";
                $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}



    $receivedpack = decode_base64($receivedpack);
    $receivedpack=uncompress($receivedpack);
    
    my @scndshits=split(" ",$receivedpack);
    my $peerRSAkey=$scndshits[0];
    
    
    $peerRSAkey = decode_base64($peerRSAkey);
    $peerRSAkey=uncompress($peerRSAkey);
      
    
    #Irssi::active_win()->print("RSA key " . " $peerRSAkey");
    if ( $debugging == 1 ) {
       Irssi::active_win()->print("RSA key \n" . "$peerRSAkey");
    }
    open(PEERRSAKEY,">$peerPUBRSAkey");
    print PEERRSAKEY "$peerRSAkey";
    close(PEERRSAKEY);
       
     my $signedMACcollec = decode_base64($scndshits[1]);
       
       
    open(SIGNATURE,">$signedMAC");
    print SIGNATURE "$signedMACcollec";
    close(SIGNATURE);

     eval{$signedMACcollec=`openssl rsautl -verify -pubin -inkey "$peerPUBRSAkey" -in "$signedMAC" 2>>$errorlog `};
     	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong generating it, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> Verification Done. ");
		  }
      if ( !($signedMACcollec) or (length($signedMACcollec) < 32) ) {
		 Irssi::active_win()->print("\00304## ATTENTION SOMETHING WENT WRONG WHILST VERIFYING WITH YOUR PEER'S RSA PUBLIC KEY ## ");
		 return 1;
	 }

     $signedMACcollec=pack("H*",$signedMACcollec);
        

     my @thrdshits=split(" ",$signedMACcollec);

     
    my $dhpub;
    my @MACss;
    
            if ( -e "$dhpubkey" ) {
    open(my $fhb, '<', $dhpubkey) or die "cannot open file $dhpubkey";
    {
        local $/;
        $dhpub = <$fhb>;
    }
    close($fhb);
  }
    
 
    $MACss[0] = hmac_sha256_hex($recoverpeerkey,$firstHMACkey);
    $MACss[0]=substr($MACss[0],0,63);
 
    $MACss[1] = hmac_sha256_hex($dhpub,$firstHMACkey);
    $MACss[1]=substr($MACss[1],0,63);
  
    $MACss[2] = hmac_sha256_hex($peerRSAkey,$firstHMACkey);
    $MACss[2]=substr($MACss[2],0,63);
    
    
    if ( $thrdshits[0] eq $MACss[0]) {
		
		$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. received MAC for peer's DH public key matches ours. \n";
		

	}else{
	$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. received MAC for peer's DH public key DOESN'T LOOK GOOD. \n";
	$controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}
	    if ( $thrdshits[1] eq $MACss[1]) {
		
				$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. received MAC for my DH public key matches ours. \n";

	

	}else{
			$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. received MAC for my DH public key DOESN'T LOOK GOOD. \n";
			$controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}
	    if ( $thrdshits[2] eq $MACss[2]) {
		
				$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. received MAC for peer's RSA public key seems fine.";


	}else{
		$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. received MAC for peer's RSA public key DOESN'T LOOK GOOD. \n";
		$controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}
    
     my $rsapub;
     
    if ( -e "$RSApubKey" ) {
    open(my $fha, '<', $RSApubKey) or die "cannot open file $RSApubKey";
    {
        local $/;
        $rsapub = <$fha>;
    }
    close($fha);
  }
    
     my $myRSAfingerprint = sha256_hex(sha512($rsapub));

     my @MACs2send;
    
 
    $MACs2send[0] = hmac_sha256_hex($dhpub,$firstHMACkeyBis);
    $MACs2send[0]=substr($MACs2send[0],0,63);
 
    $MACs2send[1] = hmac_sha256_hex($recoverpeerkey,$firstHMACkeyBis);
    $MACs2send[1]=substr($MACs2send[1],0,63);
  
    $MACs2send[2] = hmac_sha256_hex($rsapub,$firstHMACkeyBis);
    $MACs2send[2]=substr($MACs2send[2],0,63);
    
    
    $rsapub=compress($rsapub);
    
    $rsapub = encode_base64($rsapub,"");
  
      
    
    my $MACcollec=join(" ",@MACs2send);
    $MACcollec=unpack("H*",$MACcollec);
    

    open(MACSEND,">$MACcollecFile");
    print MACSEND "$MACcollec";
    close(MACSEND);
    

    my $signedMACcollec2;
    eval{$signedMACcollec2=`openssl rsautl -sign -inkey "$RSAprivKey" -in "$MACcollecFile" 2>>$errorlog`};
    	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong generating it, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> Signature Done. ");
		  }
		  
	if ( !($signedMACcollec2) or (length($signedMACcollec2) < 32) ) {
		Irssi::active_win()->print("\00304> Signature Failed. ");
		return 1;
	}	  
 
    $signedMACcollec2 = encode_base64($signedMACcollec2,"");
    
    my $pack2send= $rsapub . " " . $signedMACcollec2 ;
    $pack2send=compress($pack2send);

    $pack2send = encode_base64($pack2send,"");
 
    
    my $thehashpack = hmac_sha256_hex($pack2send,$secondHMACkeyBis);

    $thehashpack=substr($thehashpack,0,40);    
    
    
    
    $cipher->{'passphrase'} = $SymmKeyBis;
    $pack2send = $cipher->encrypt($pack2send);
    $pack2send = encode_base64($pack2send,"");
    

     my $newheader = $DHgimmetheCandy . $nick . "?";
 	 splittus($server,$channel,$pack2send,$thehashpack,$newheader);
    

	    my $peerRSAfingerprint = sha256_hex(sha512($peerRSAkey));

     $peerRSAfingerprint =~ s/(\p{Hex}{4})\B/$1-/g;
     $peerRSAfingerprint =~ s/([a-z])/\u$1/g ;
     
	Irssi::active_win()->print("Control Log Summary: \n". $controlbit{ $servaddr}{$nick}{'checkpoints'} );
	
	if ( $controlbit{ $servaddr}{$nick}{'checkpointbits'} eq 'Cool') {
		
		Irssi::active_win()->print("\00305YOU SUCCEED THIS KEY EXCHANGE PROCESS. READY TO GO.");
		my $stk = $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecret'} . " " . $nick ;
		setkey3($stk,$server,$channel);
		$permchans{$servaddr}{$channel} = 1;
	}else{
		Irssi::active_win()->print("\00305YOU EPIC FAILED THIS KEY EXCHANGE PROCESS, PUT YOUR TIN FOIL HAT ON AND DESTROY ALL EVIDENCE NOW!!! FUCKING FEDS");
		return 1;
		}

	Irssi::active_win()->print("Your Peer's Fingerprint is :  \00315" . "$peerRSAfingerprint");
	


	 $myRSAfingerprint =~ s/(\p{Hex}{4})\B/$1-/g;
     $myRSAfingerprint =~ s/([a-z])/\u$1/g ;	
     	

	Irssi::active_win()->print("Your Own Fingerprint is :     \00315" . "$myRSAfingerprint");
	

    open(T,">>$peerRSAfingerprintHistory");
	#print T "$peerRSAfingerprint\n";
    print T "$peerRSAfingerprint   " . gmtime() . "\n";  ## revert if you dont want to timestamp
	close(T);

      my @hist;
	open(F,"<$peerRSAfingerprintHistory");
    @hist = <F>;
	close(F);
	
	my $totl = scalar(@hist);
	if ( $totl >= 2 ) {
		my $chkfg = @hist[($totl - 2)];
		my @chkng = split(" ",$chkfg);
		if ( $chkng[0] eq $peerRSAfingerprint ) {
			Irssi::active_win()->print("\00304The current fingerprint of your peer's RSA key matches the one from the previous key he used. \00303Everything looks OK");
		}else{
			Irssi::active_win()->print("\00305The current fingerprint of your peer's RSA key DOESN'T MATCH the one from the previous key he used. so..IT'S NOT THE SAME RSA KEY... fishy");
		}
		Irssi::active_win()->print("Previous fingerprints for the RSA keys used by your peer were: \n");
		for (my $i=2;$i<5 and $i <= $totl;$i++) {
		
	         Irssi::active_win()->print($hist[($totl-$i)]);
       }
	
	}
	
	
		my $randptt = Crypt::CBC->random_bytes('2048');
		  if ( -e "$dhprivkey" ) {
		    open(PRF, '>', $dhprivkey) or die "cannot open file $dhprivkey";
		    print PRF $randptt;
		    close(PRF);
		  }	
		  if ( -e "$dhpubkey" ) {
		    open(PUF, '>', $dhpubkey) or die "cannot open file $dhpubkey";
		    print PUF $randptt;
		    close(PUF);
		  }
		  if ( -e "$peerkey" ) {
		    open(PEF, '>', $peerkey) or die "cannot open file $peerkey";
		    print PEF $randptt;
		    close(PEF);
		  }     
			          
		  if ( -e "$MACcollecFile" ) {
		    open(M, '>', $MACcollecFile) or die "cannot open file $MACcollecFile";
		    print M $randptt;
		    close(M);
		  }
		  if ( -e "$signedMAC" ) {
		    open(SM, '>', $signedMAC) or die "cannot open file $signedMAC";
		    print SM $randptt;
		    close(SM);
		  }	
	
	

	    Irssi::active_win()->print("Your Shared Passphrase with $nick: \00304" . $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecret'});
	    
        Irssi::active_win()->print("Passphrase to use with $nick for File encryption: \00304" . $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecretFile'} );



}
## < k`> i like tentacle pr0n :D

sub I_cant_get_Satisfaction {
	
		my ($server, $msg, $nick, $channel) = @_;
	
	     my $servaddr = $server->{address};	
	     my $prefixf = hashing_shits($nick,$servaddr);

	     
	     my $dhparamfile = $folder."dh-4096.pem";
	     
		 my $dhprivkey = $convofolder . $prefixf . "-dhprivatekey";
		 my $dhpubkey = $convofolder . $prefixf . "-dhpubkey";
		 my $peerkey = $convofolder . $prefixf . "-dhpeerkey";
		 
		 my $RSAprivKey = $folder."RSAprivateKey";
	     my $RSApubKey = $folder."RSApublicKey";
	     
	     my $peerPUBRSAkey = $friendsfolder . $prefixf . "-peerRSApublicKey";
	     
	     my $MACcollecFile = $convofolder. $prefixf . "-MACcollec";
	     my $signedMAC = $convofolder . $prefixf . "-signedMACs";
	     
	     my $peerRSAfingerprintHistory = $friendsfolder . $prefixf . "-peerRSAfingerprintsHistory";
	     	     
			 	 
		   	 my @data;
		   	 @data=split(" ",$msg);
	 shift @data;
	 
	 my $out;
             	     my $hashmsg;
             	    
        ($out,$hashmsg) = get_all_together($server,join(" ",@data),$channel,$nick);

     if(!$out) {
		        Irssi::signal_stop();
                return;
		 }
		 
		 if(! length($out))
    {
       
       

       Irssi::signal_stop();
       return;
    }
        

	Irssi::signal_stop();
	
	
	   my $receivedpack=$out;
  

       my $SymmKeyBis=$AKE{ $servaddr}{$nick}{'stuff'}{'SymmKeyBis'};
       
       my $firstHMACkeyBis=$AKE{ $servaddr}{$nick}{'stuff'}{'firstHMACkeyBis'};
       
       my $secondHMACkeyBis=$AKE{ $servaddr}{$nick}{'stuff'}{'secondHMACkeyBis'};
       
       

    Irssi::signal_stop();
    
    $cipher->{'passphrase'} = $SymmKeyBis;
    $receivedpack = decode_base64($receivedpack);
    $receivedpack = $cipher->decrypt($receivedpack);
    
    
    my $recvhashpack = hmac_sha256_hex($receivedpack,$secondHMACkeyBis);

    $recvhashpack=substr($recvhashpack,0,40);
          
    
    	if ( $recvhashpack eq $hashmsg) {
		    $controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. HMAC for decrypted package with peer's RSA public key and MACs looks fine. \n";


	}else{
	  $controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. HMAC for decrypted package with peer's RSA public key and MACs DOESN'T LOOK GOOD. \n";
      $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
		
	}
    
    
    
    
 
  
    $receivedpack = decode_base64($receivedpack);
    $receivedpack=uncompress($receivedpack);
    
    my @scndshits=split(" ",$receivedpack);
    my $peerRSAkey=$scndshits[0];
    
    
    $peerRSAkey = decode_base64($peerRSAkey);
    $peerRSAkey = uncompress($peerRSAkey);
     
    
    if ( $debugging == 1 ) {
       Irssi::active_win()->print("RSA key \n" . "$peerRSAkey");
    }
    open(PEERRSAKEY,">$peerPUBRSAkey");
    print PEERRSAKEY "$peerRSAkey";
    close(PEERRSAKEY);
    
    
    
     my $signedMACcollec = decode_base64($scndshits[1]);
       
       
    open(SIGNATURE,">$signedMAC");
    print SIGNATURE "$signedMACcollec";
    close(SIGNATURE);

     eval{$signedMACcollec=`openssl rsautl -verify -pubin -inkey "$peerPUBRSAkey" -in "$signedMAC" 2>>$errorlog`};
     	  if ($@) {
		  	 Irssi::active_win()->print("\00305> Something went wrong verifying it, please retry later. ");

	  }else {
		  Irssi::active_win()->print("\00305> Verification Done. ");
		  }
     if ( !($signedMACcollec) or (length($signedMACcollec) < 32) ) {
		 Irssi::active_win()->print("\00304## ATTENTION SOMETHING WENT WRONG WHILST VERIFYING WITH YOUR PEER'S RSA PUBLIC KEY ## ");
		 return 1;
	 }
    
     $signedMACcollec=pack("H*",$signedMACcollec);
      

     my @thrdshits=split(" ",$signedMACcollec);

     
       
     my $dhpub;
     my $dhpeerpub;  
       

 
        if ( -e "$dhpubkey" ) {
    open(my $fhb, '<', $dhpubkey) or die "cannot open file $dhpubkey";
    {
        local $/;
        $dhpub = <$fhb>;
    }
    close($fhb);
  }
      if ( -e "$peerkey" ) {
    open(my $fhc, '<', $peerkey) or die "cannot open file $peerkey";
    {
        local $/;
        $dhpeerpub = <$fhc>;
    }
    close($fhc);
  }
       
              
       
    my @MACss;
    
 
    $MACss[0]= hmac_sha256_hex($dhpeerpub,$firstHMACkeyBis);
    $MACss[0]=substr($MACss[0],0,63);
 
    $MACss[1]= hmac_sha256_hex($dhpub,$firstHMACkeyBis);
    $MACss[1]=substr($MACss[1],0,63);
 
    $MACss[2]= hmac_sha256_hex($peerRSAkey,$firstHMACkeyBis);
    $MACss[2]=substr($MACss[2],0,63);
    

    
    if ( $thrdshits[0] eq $MACss[0]) {
				$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. received MAC for peer's DH public key matches ours. \n";


	}else{
			  $controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. received MAC for peer's DH public key DOESN'T LOOK GOOD. \n";
			  $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}
	    if ( $thrdshits[1] eq $MACss[1]) {
						$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. received MAC for my DH public key matches ours. \n";


	}else{
			  $controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. received MAC for my DH public key DOESN'T LOOK GOOD. \n";
			  $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}
	    if ( $thrdshits[2] eq $MACss[2]) {
						$controlbit{ $servaddr}{$nick}{'checkpoints'} .= "OK. received MAC for peer's RSA public key seems fine.";


	}else{
			  $controlbit{ $servaddr}{$nick}{'checkpoints'} .= "NOT GOOD. received MAC for peer's RSA public key DOESN'T LOOK GOOD. \n";
			  $controlbit{ $servaddr}{$nick}{'checkpointbits'} = 'MegaFailure';
}
	
     my $rsapub;
     
    if ( -e "$RSApubKey" ) {
    open(my $fha, '<', $RSApubKey) or die "cannot open file $RSApubKey";
    {
        local $/;
        $rsapub = <$fha>;
    }
    close($fha);
  }
	

    Irssi::active_win()->print("Control Log Summary: \n". $controlbit{ $servaddr}{$nick}{'checkpoints'} );
    
    	if ( $controlbit{ $servaddr}{$nick}{'checkpointbits'} eq 'Cool') {
		
		Irssi::active_win()->print("\00305YOU SUCCEED THIS KEY EXCHANGE PROCESS. READY TO GO.");
		my $stk = $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecret'} . " " . $nick ;
		setkey3($stk,$server,$channel);
		$permchans{$servaddr}{$channel} = 1;
	}else{
		Irssi::active_win()->print("\00305YOU EPIC FAILED THIS KEY EXCHANGE PROCESS, PUT YOUR TIN FOIL HAT ON AND DESTROY ALL EVIDENCE NOW!!! FUCKING FEDS");
		return 1;
		}
	 
	 my $peerRSAfingerprint = sha256_hex(sha512($peerRSAkey));
	 
	 $peerRSAfingerprint =~ s/(\p{Hex}{4})\B/$1-/g;
     $peerRSAfingerprint =~ s/([a-z])/\u$1/g ;
	
	
	Irssi::active_win()->print("Your Peer's Fingerprint is :  \00315" . "$peerRSAfingerprint");
	
	 
	 my $myRSAfingerprint = sha256_hex(sha512($rsapub));
	 
	 $myRSAfingerprint =~ s/(\p{Hex}{4})\B/$1-/g;
     $myRSAfingerprint =~ s/([a-z])/\u$1/g ;	
	
	Irssi::active_win()->print("Your Own Fingerprint is :     \00315" . "$myRSAfingerprint");
	
	open(T,">>$peerRSAfingerprintHistory");
	#print T "$peerRSAfingerprint \n";
	print T "$peerRSAfingerprint   " . gmtime() . "\n";
	close(T);
	
	

    my @hist;
	open(F,"<$peerRSAfingerprintHistory");
    @hist = <F>;
	close(F);
	
	my $totl = scalar(@hist);
	if ( $totl >= 2 ) {
		my $chkfg = @hist[($totl - 2)];
		my @chkng = split(" ",$chkfg);
		if ( $chkng[0] eq $peerRSAfingerprint ) {
			Irssi::active_win()->print("\00304The current fingerprint of your peer's RSA key matches the one from the previous key he used. \00303Everything looks OK");
		}else{
			Irssi::active_win()->print("\00305The current fingerprint of your peer's RSA key DOESN'T MATCH the one from the previous key he used. so..IT'S NOT THE SAME RSA KEY... fishy");
		}
		Irssi::active_win()->print("Previous fingerprints for the RSA keys used by your peer were: \n");
		for (my $i=2;$i<5 and $i <= $totl;$i++) {
		
	Irssi::active_win()->print($hist[($totl-$i)]);
    }
	
	}
	
		my $randptt = Crypt::CBC->random_bytes('2048');
		  if ( -e "$dhprivkey" ) {
		    open(PRF, '>', $dhprivkey) or die "cannot open file $dhprivkey";
		    print PRF $randptt;
		    close(PRF);
		  }	
		  if ( -e "$dhpubkey" ) {
		    open(PUF, '>', $dhpubkey) or die "cannot open file $dhpubkey";
		    print PUF $randptt;
		    close(PUF);
		  }
		  if ( -e "$peerkey" ) {
		    open(PEF, '>', $peerkey) or die "cannot open file $peerkey";
		    print PEF $randptt;
		    close(PEF);
		  }     
			          
		  if ( -e "$MACcollecFile" ) {
		    open(M, '>', $MACcollecFile) or die "cannot open file $MACcollecFile";
		    print M $randptt;
		    close(M);
		  }
		  if ( -e "$signedMAC" ) {
		    open(SM, '>', $signedMAC) or die "cannot open file $signedMAC";
		    print SM $randptt;
		    close(SM);
		  }
	
	
	    Irssi::active_win()->print("Your Shared Passphrase with $nick: \00304" . $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecret'});
	    
        Irssi::active_win()->print("Passphrase to use with $nick for File encryption: \00304" . $candidatesharedsecret{ $servaddr}{$nick}{'superCoolsecretFile'} );


}


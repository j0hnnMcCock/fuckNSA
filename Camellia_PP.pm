package Crypt::Camellia_PP;

use strict;
use warnings;
use Carp;
our $VERSION = '0.02';

my $SIGMA1 = [ 0xA0, 0x9E, 0x66, 0x7F, 0x3B, 0xCC, 0x90, 0x8B ];
my $SIGMA2 = [ 0xB6, 0x7A, 0xE8, 0x58, 0x4C, 0xAA, 0x73, 0xB2 ];
my $SIGMA3 = [ 0xC6, 0xEF, 0x37, 0x2F, 0xE9, 0x4F, 0x82, 0xBE ];
my $SIGMA4 = [ 0x54, 0xFF, 0x53, 0xA5, 0xF1, 0xD3, 0x6F, 0x1C ];
my $SIGMA5 = [ 0x10, 0xE5, 0x27, 0xFA, 0xDE, 0x68, 0x2D, 0x1D ];
my $SIGMA6 = [ 0xB0, 0x56, 0x88, 0xC2, 0xB3, 0xE6, 0xC1, 0xFD ];

my @S1 = (
    112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
     35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
    134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
    166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
    139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
    223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
     20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
    254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
    170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
     16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
    135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
     82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
    233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
    120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
    114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
     64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158
);
my @S2 = (
    224,5,88,217,103,78,129,203,201,11,174,106,213,24,93,130,
    70,223,214,39,138,50,75,66,219,28,158,156,58,202,37,123,
    13,113,95,31,248,215,62,157,124,96,185,190,188,139,22,52,
    77,195,114,149,171,142,186,122,179,2,180,173,162,172,216,154,
    23,26,53,204,247,153,97,90,232,36,86,64,225,99,9,51,
    191,152,151,133,104,252,236,10,218,111,83,98,163,46,8,175,
    40,176,116,194,189,54,34,56,100,30,57,44,166,48,229,68,
    253,136,159,101,135,107,244,35,72,16,209,81,192,249,210,160,
    85,161,65,250,67,19,196,47,168,182,60,43,193,255,200,165,
    32,137,0,144,71,239,234,183,21,6,205,181,18,126,187,41,
    15,184,7,4,155,148,33,102,230,206,237,231,59,254,127,197,
    164,55,177,76,145,110,141,118,3,45,222,150,38,125,198,92,
    211,242,79,25,63,220,121,29,82,235,243,109,94,251,105,178,
    240,49,12,212,207,140,226,117,169,74,87,132,17,69,27,245,
    228,14,115,170,241,221,89,20,108,146,84,208,120,112,227,73,
    128,80,167,246,119,147,134,131,42,199,91,233,238,143,1,61
);
my @S3 = (
    56,65,22,118,217,147,96,242,114,194,171,154,117,6,87,160,
    145,247,181,201,162,140,210,144,246,7,167,39,142,178,73,222,
    67,92,215,199,62,245,143,103,31,24,110,175,47,226,133,13,
    83,240,156,101,234,163,174,158,236,128,45,107,168,43,54,166,
    197,134,77,51,253,102,88,150,58,9,149,16,120,216,66,204,
    239,38,229,97,26,63,59,130,182,219,212,152,232,139,2,235,
    10,44,29,176,111,141,136,14,25,135,78,11,169,12,121,17,
    127,34,231,89,225,218,61,200,18,4,116,84,48,126,180,40,
    85,104,80,190,208,196,49,203,42,173,15,202,112,255,50,105,
    8,98,0,36,209,251,186,237,69,129,115,109,132,159,238,74,
    195,46,193,1,230,37,72,153,185,179,123,249,206,191,223,113,
    41,205,108,19,100,155,99,157,192,75,183,165,137,95,177,23,
    244,188,211,70,207,55,94,71,148,250,252,91,151,254,90,172,
    60,76,3,53,243,35,184,93,106,146,213,33,68,81,198,125,
    57,131,220,170,124,119,86,5,27,164,21,52,30,28,248,82,
    32,20,233,189,221,228,161,224,138,241,214,122,187,227,64,79
);
my @S4 = (
    112,44,179,192,228,87,234,174,35,107,69,165,237,79,29,146,
    134,175,124,31,62,220,94,11,166,57,213,93,217,90,81,108,
    139,154,251,176,116,43,240,132,223,203,52,118,109,169,209,4,
    20,58,222,17,50,156,83,242,254,207,195,122,36,232,96,105,
    170,160,161,98,84,30,224,100,16,0,163,117,138,230,9,221,
    135,131,205,144,115,246,157,191,82,216,200,198,129,111,19,99,
    233,167,159,188,41,249,47,180,120,6,231,113,212,171,136,141,
    114,185,248,172,54,42,60,241,64,211,187,67,21,173,119,128,
    130,236,39,229,133,53,12,65,239,147,25,33,14,78,101,189,
    184,143,235,206,48,95,197,26,225,202,71,61,1,214,86,77,
    13,102,204,45,18,32,177,153,76,194,126,5,183,49,23,215,
    88,97,27,28,15,22,24,34,68,178,181,145,8,168,252,80,
    208,125,137,151,91,149,255,210,196,72,247,219,3,218,63,148,
    92,2,74,51,103,243,127,226,155,38,55,59,150,75,190,46,
    121,140,110,142,245,182,253,89,152,106,70,186,37,66,162,250,
    7,85,238,10,73,104,56,164,40,123,201,193,227,244,199,158
);


sub blocksize { 16 }
sub keysize { 32 }



sub new {
    my $class = shift;
    my $key   = shift;
    if (!defined $key) {
        croak q{Usage: Crypt::Camellia_PP->new($key);};
    }
    my $keysize = length $key;
    if ($keysize != 16 && $keysize != 24 && $keysize != 32) {
        croak q{wrong key length: key must be 128, 192 or 256 bit.};
    }

    my @key = unpack 'C*', $key;
    my $self = bless {
        keysize => $keysize,
        kw      => [
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0]
        ],
        k       => [
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0]
        ],
        kl      => [
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0]
        ]
    }, $class;
    $self->_prepare_sub_key(\@key);
    return $self;
}


sub encrypt {
    my $self = shift;
    my $in = shift;
    my $l = [ unpack 'C8', $in ];
    my $r = [ unpack 'C8', substr $in, 8, 8];
    _xor_block($l, $l, $self->{kw}->[0], 8);
    _xor_block($r, $r, $self->{kw}->[1], 8);
    if ($self->{keysize} == 16) {
        for (my $i = 0; $i < 18; $i += 2) {
            _feistel($r, 0, $l, $self->{k}->[$i]);
            _feistel($l, 0, $r, $self->{k}->[$i+1]);
            if ($i == 4) { # round 6
                _flayer($l, $l, $self->{kl}->[0], 0);
                _flayer_1($r, $r, $self->{kl}->[1], 0);
            }
            elsif ($i == 10) { # round 12
                _flayer($l, $l, $self->{kl}->[2], 0);
                _flayer_1($r, $r, $self->{kl}->[3], 0);
            }
        }
    }
    else {
        for (my $i = 0; $i < 24; $i += 2) {
            _feistel($r, 0, $l, $self->{k}->[$i]);
            _feistel($l, 0, $r, $self->{k}->[$i+1]);
            if ($i == 4) { # round 6
                _flayer($l, $l, $self->{kl}->[0], 0);
                _flayer_1($r, $r, $self->{kl}->[1], 0);
            }
            elsif ($i == 10) { # round 12
                _flayer($l, $l, $self->{kl}->[2], 0);
                _flayer_1($r, $r, $self->{kl}->[3], 0);
            }
            elsif ($i == 16) { # round 18
                _flayer($l, $l, $self->{kl}->[4], 0);
                _flayer_1($r, $r, $self->{kl}->[5], 0);
            }
        }
    }
    _xor_block($r, $r, $self->{kw}->[2], 8);
    _xor_block($l, $l, $self->{kw}->[3], 8);

    return pack 'C16', @$r, @$l;
}


sub decrypt {
    my $self = shift;
    my $in = shift;

    my $r = [ unpack 'C8', $in ];
    my $l = [ unpack 'C8', substr $in, 8, 8];
    _xor_block($r, $r, $self->{kw}->[2], 8);
    _xor_block($l, $l, $self->{kw}->[3], 8);
    if ($self->{keysize} == 16) {
        for (my $i = 16; $i >= 0; $i -= 2) {
            _feistel($l, 0, $r, $self->{k}->[$i+1]);
            _feistel($r, 0, $l, $self->{k}->[$i]);
            if ($i == 12) {
                _flayer($r, $r, $self->{kl}->[3]);
                _flayer_1($l, $l, $self->{kl}->[2]);
            }
            elsif ($i == 6) {
                _flayer($r, $r, $self->{kl}->[1]);
                _flayer_1($l, $l, $self->{kl}->[0]);
            }
        }
    }
    else {
        for (my $i = 22; $i >= 0; $i -= 2) {
            _feistel($l, 0, $r, $self->{k}->[$i+1]);
            _feistel($r, 0, $l, $self->{k}->[$i]);
            if ($i == 18) {
                _flayer($r, $r, $self->{kl}->[5]);
                _flayer_1($l, $l, $self->{kl}->[4]);
            }
            elsif ($i == 12) {
                _flayer($r, $r, $self->{kl}->[3]);
                _flayer_1($l, $l, $self->{kl}->[2]);
            }
            elsif ($i == 6) {
                _flayer($r, $r, $self->{kl}->[1]);
                _flayer_1($l, $l, $self->{kl}->[0]);
            }
        }

    }
    _xor_block($l, $l, $self->{kw}->[0], 8);
    _xor_block($r, $r, $self->{kw}->[1], 8);

    return pack 'C16', @$l, @$r;
}



sub _prepare_sub_key {
    my $self = shift;
    my $key = shift;
    my $kl = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    my $kr = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    my $ka = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]; 

    if ($self->{keysize} == 16) {
        _move($kl, 0, $key, 0, 16);
    }
    elsif ($self->{keysize} == 24) {
        _move($kl, 0, $key, 0, 16); 
        _move($kr, 0, $key, 16, 8); 
        for (my $i = 0; $i < 8; $i++) {
            $kr->[$i+8] = $key->[$i+16] ^ 0xff;
        }
    }
    elsif ($self->{keysize} == 32) {
        _move($kl, 0, $key, 0, 16); 
        _move($kr, 0, $key, 16,16); 
    }
   
    _xor_block($ka, $kl, $kr, 16);
    _feistel($ka, 8, $ka, $SIGMA1);
    _feistel($ka, 0, [@$ka[8..15]], $SIGMA2);
    _xor_block($ka, $kl, $ka, 16);

    _feistel($ka, 8, $ka, $SIGMA3);
    _feistel($ka, 0, [@$ka[8..15]], $SIGMA4);

    if ($self->{keysize} == 16) {
        _rot_shift($self->{kw}->[0], $self->{kw}->[1], $kl, 0);
    
        _rot_shift($self->{k}->[0], $self->{k}->[1], $ka, 0);
        _rot_shift($self->{k}->[2], $self->{k}->[3], $kl, 15);
        _rot_shift($self->{k}->[4], $self->{k}->[5], $ka, 15);
        
        _rot_shift($self->{kl}->[0], $self->{kl}->[1], $ka, 30);
      
        _rot_shift($self->{k}->[6], $self->{k}->[7], $kl, 45);
        _rot_shift($self->{k}->[8], [0,0,0,0,0,0,0,0], $ka, 45);
        _rot_shift([0,0,0,0,0,0,0,0], $self->{k}->[9], $kl, 60);
        _rot_shift($self->{k}->[10], $self->{k}->[11], $ka, 60);
    
        _rot_shift($self->{kl}->[2], $self->{kl}->[3], $kl, 77);
      
        _rot_shift($self->{k}->[12], $self->{k}->[13], $kl, 94);
        _rot_shift($self->{k}->[14], $self->{k}->[15], $ka, 94);
        _rot_shift($self->{k}->[16], $self->{k}->[17], $kl, 111);
        
        _rot_shift($self->{kw}->[2], $self->{kw}->[3], $ka, 111);
    }
    else {
        my $kb = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        _xor_block($kb, $kr, $ka, 16);
        _feistel($kb, 8, $kb, $SIGMA5);
        _feistel($kb, 0, [@$kb[8..15]], $SIGMA6);

        _rot_shift($self->{kw}->[0], $self->{kw}->[1], $kl, 0);

        _rot_shift($self->{k}->[0], $self->{k}->[1], $kb, 0);
        _rot_shift($self->{k}->[2], $self->{k}->[3], $kr, 15);
        _rot_shift($self->{k}->[4], $self->{k}->[5], $ka, 15);

        _rot_shift($self->{kl}->[0], $self->{kl}->[1], $kr, 30);

        _rot_shift($self->{k}->[6], $self->{k}->[7], $kb, 30);
        _rot_shift($self->{k}->[8], $self->{k}->[9], $kl, 45);
        _rot_shift($self->{k}->[10], $self->{k}->[11], $ka, 45);

        _rot_shift($self->{kl}->[2], $self->{kl}->[3], $kl, 60);

        _rot_shift($self->{k}->[12], $self->{k}->[13], $kr, 60);
        _rot_shift($self->{k}->[14], $self->{k}->[15], $kb, 60);
        _rot_shift($self->{k}->[16], $self->{k}->[17], $kl, 77);

        _rot_shift($self->{kl}->[4], $self->{kl}->[5], $ka, 77);

        _rot_shift($self->{k}->[18], $self->{k}->[19], $kr, 94);
        _rot_shift($self->{k}->[20], $self->{k}->[21], $ka, 94);
        _rot_shift($self->{k}->[22], $self->{k}->[23], $kl, 111);

        _rot_shift($self->{kw}->[2], $self->{kw}->[3], $kb, 111);
    }

    return $self;
}



sub _move {
    for (my $i = 0; $i < $_[4]; $i++) {
        $_[0]->[$i+$_[1]] = $_[2]->[$i+$_[3]];
    }
}


sub _xor_block {
    for (my $i = 0; $i < $_[3]; $i++) {
        $_[0]->[$i] = $_[1]->[$i] ^ $_[2]->[$i];
    }
}


sub _feistel {
    my $dist = shift;
    my $o = shift;
    my $x = shift;
    my $k = shift;
    my $w = [0,0,0,0,0,0,0,0];
    _xor_block($w, $x, $k, 8);
    # S funcs
    my @ws = ($S1[$w->[0]], $S2[$w->[1]], $S3[$w->[2]], $S4[$w->[3]],
              $S2[$w->[4]], $S3[$w->[5]], $S4[$w->[6]], $S1[$w->[7]]);
    # P func
    $dist->[0+$o] ^= $ws[0] ^ $ws[2] ^ $ws[3] ^ $ws[5] ^ $ws[6] ^ $ws[7];
    $dist->[1+$o] ^= $ws[0] ^ $ws[1] ^ $ws[3] ^ $ws[4] ^ $ws[6] ^ $ws[7];
    $dist->[2+$o] ^= $ws[0] ^ $ws[1] ^ $ws[2] ^ $ws[4] ^ $ws[5] ^ $ws[7];
    $dist->[3+$o] ^= $ws[1] ^ $ws[2] ^ $ws[3] ^ $ws[4] ^ $ws[5] ^ $ws[6];
    $dist->[4+$o] ^= $ws[0] ^ $ws[1] ^ $ws[5] ^ $ws[6] ^ $ws[7];
    $dist->[5+$o] ^= $ws[1] ^ $ws[2] ^ $ws[4] ^ $ws[6] ^ $ws[7];
    $dist->[6+$o] ^= $ws[2] ^ $ws[3] ^ $ws[4] ^ $ws[5] ^ $ws[7];
    $dist->[7+$o] ^= $ws[0] ^ $ws[3] ^ $ws[4] ^ $ws[5] ^ $ws[6];
}


sub _flayer {
    my ($dist, $x, $k) = @_;
    _move($dist, 0, $x, 0, 8);
    $dist->[4+0] ^= ((($x->[0] & $k->[0]) << 1) & 0xff) ^ ($x->[1] & $k->[1]) >> 7;
    $dist->[4+1] ^= ((($x->[1] & $k->[1]) << 1) & 0xff) ^ ($x->[2] & $k->[2]) >> 7;
    $dist->[4+2] ^= ((($x->[2] & $k->[2]) << 1) & 0xff) ^ ($x->[3] & $k->[3]) >> 7;
    $dist->[4+3] ^= ((($x->[3] & $k->[3]) << 1) & 0xff) ^ ($x->[0] & $k->[0]) >> 7;
    $dist->[0] ^= $dist->[4+0] | $k->[4+0];
    $dist->[1] ^= $dist->[4+1] | $k->[4+1];
    $dist->[2] ^= $dist->[4+2] | $k->[4+2];
    $dist->[3] ^= $dist->[4+3] | $k->[4+3];
}


sub _flayer_1 {
    my ($dist, $x, $k) = @_;
    _move($dist, 0, $x, 0, 8);
    $dist->[0] ^= $x->[4+0] | $k->[4+0];
    $dist->[1] ^= $x->[4+1] | $k->[4+1];
    $dist->[2] ^= $x->[4+2] | $k->[4+2];
    $dist->[3] ^= $x->[4+3] | $k->[4+3];
    $dist->[4+0] ^= ((($dist->[0] & $k->[0]) << 1) & 0xff) ^ ($dist->[1] & $k->[1]) >> 7;
    $dist->[4+1] ^= ((($dist->[1] & $k->[1]) << 1) & 0xff) ^ ($dist->[2] & $k->[2]) >> 7;
    $dist->[4+2] ^= ((($dist->[2] & $k->[2]) << 1) & 0xff) ^ ($dist->[3] & $k->[3]) >> 7;
    $dist->[4+3] ^= ((($dist->[3] & $k->[3]) << 1) & 0xff) ^ ($dist->[0] & $k->[0]) >> 7;
}


sub _rot_shift {
    my ($dist_l, $dist_r, $src, $bit) = @_;
    if ($bit == 0) {
        for (my $i = 0; $i < 8; $i++) {
            $dist_l->[$i] = $src->[$i];
        }
        for (my $i = 0; $i < 8; $i++) {
            $dist_r->[$i] = $src->[$i+8];
        }
        return;
    }
    my $o = int($bit / 8) + 1;
    my $so = $o * 8 - $bit;
    $o = $o % 16;
    for (my $i = 0; $i < 8; $i++) {
        $dist_l->[$i] = (($src->[($i+$o) % 16] >> $so) & 0xff)
                    | (($src->[($i+$o-1) % 16] << (8 - $so)) & 0xff);
        $dist_r->[$i] = (($src->[($i+8+$o) % 16] >> $so) & 0xff)
                    | (($src->[($i+8+$o-1) % 16] << (8 - $so)) & 0xff);
    }
}

1;
__END__

=head1 NAME

Crypt::Camellia_PP - Pure Perl Camellia 128-bit block cipher module.

=head1 SYNOPSIS

  use Crypt::Camellia_PP;
 
  my $key = pack 'H*', '00000000000000000000000000000000'; 
  my $plain_text = pack 'H*', '00000000000000000000000000000000';
  my $c = Crypt::Camellia->new($key);
  my $cipher_text = $c->encrypt($plain_text);
  

=head1 DESCRIPTION

this module implements the Camellia cipher by Pure Perl.

=head2 Methods

=over 4

=item new($key)

Create a new "Crypt::Camellia_PP" cipher object with the given key (which must be 128 or 192 or 256 bit long).

=item encrypt($data)

Encrypt data. The size of $data must be a 16 bytes.

=item decrypt($data)

Decrypts $data.

=back

=head1 EXAMPLE

=head2 Encrypt and Decrypt

  use Crypt::Camellia_PP;
  
  my $key = pack 'H*', '00112233445566778899AABBCCDDEEFF';
  my $src = pack 'H*', 'FFEEDDCCBBAA99887766554433221100';
  my $camellia = Crypt::Camellia_PP->new($key);
  my $cipher_string = $camellia->encrypt($src);
  
  my $plain_string = $camellia->decrypt($cipher_string);
  $plain_string eq $src;

=head2 With Crypt::CBC module

  use Crypt::CBC;
  
  my $cbc = Crypt::CBC->new({
      cipher => 'Crypt::Camellia_PP',
      key => pack('H*', '00112233445566778899aabbccddeeff'),
      iv  => pack('H*', '00000000000000000000000000000000'),
      literal_key => 1,
      header => 'none',
      padding => 'standard',
  });
  my $cipher_text = $cbc->encrypt('Hello World!');
  my $plain_text = $cbc->decrypt($cipher_text);
  $plain_text eq 'Hello World!';

=head1 SEE ALSO

L<Crypt::Camellia>,
http://search.cpan.org/dist/Crypt-Camellia/,
http://info.isl.ntt.co.jp/crypt/camellia/

=head1 AUTHOR

Hiroyuki OYAMA E<lt>oyama@module.jpE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Hiroyuki OYAMA. Japan.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

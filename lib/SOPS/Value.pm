package SOPS::Value;
use Moo;
use MIME::Base64 qw(decode_base64 encode_base64);
use Crypt::AuthEnc::GCM;
use Crypt::PRNG::ChaCha20 qw(random_bytes);
use JSON 2 ();
use Scalar::Util qw(looks_like_number);

has 'data' => ( is => 'ro', predicate => 1 );
has 'iv'   => ( is => 'ro' );
has 'tag'  => ( is => 'ro' );
has 'type' => ( is => 'ro' );

my $base64 = qr{
    ^
    (?: [A-Za-z0-9+/]{4} )*
    (?:
        [A-Za-z0-9+/]{2} [AEIMQUYcgkosw048] =
    |
        [A-Za-z0-9+/] [AQgw] ==
    )?
    \z
}x;
$base64 = qr{.+};

my $encre = qr/^ENC\[AES256_GCM,data:($base64),iv:($base64),tag:($base64),type:(.+)\]/;

sub parse {
  my ($class, $value) = @_;
  my (@matches);
  if (@matches = $value =~ $encre) {
    my %init = (
        data => decode_base64($matches[0]),
        iv   => decode_base64($matches[1]),
        tag  => decode_base64($matches[2]),
        type => $matches[3],
    );
    return $class->new(%init);
  }
  elsif (length $value == 0) {
      return $class->new;
  }
  else {
    die "Input string $value does not match sops' data format";
  }
}

sub to_string {
    my ($self) = @_;
    return "" unless $self->has_data;
    return sprintf "ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
        encode_base64( $self->data, "" ),
        encode_base64( $self->iv,   "" ),
        encode_base64( $self->tag,  "" ),
        $self->type;
}

use constant IV_SIZE => 32;

my %BOOL = ( True => JSON->true, False => JSON->false );

sub decrypt {
    my ($self, $key, $path, $stash) = @_;

    return "" unless $self->has_data;

    my $gcm = Crypt::AuthEnc::GCM->new('AES', $key, $self->iv);
    $stash->{iv} = $self->iv;
    $gcm->adata_add($path);
    my $decrypted_value = $gcm->decrypt_add($self->data);

    if ($gcm->decrypt_done($self->tag)) {
        my $type = $self->type;
        if ($type eq 'bool') {
            return $BOOL{$decrypted_value};
        } else {
            return $decrypted_value;
        }
    } else {
        return "";
    }
}

sub encrypt {
    my ($class, $value, $key, $path, $stash ) = @_;

    my $iv = $stash && $stash->{plaintext} eq $value ? $stash->{iv} : random_bytes(IV_SIZE);

    return $class->new() unless length $value;

    my $type;
    my $plaintext;
    if ( JSON::is_bool($value) ) {
        $type = 'bool';
        $plaintext = $value ? 'True' : 'False';
    }
    elsif ( looks_like_number($value) ) {
        if ( int($value) == $value ) {
            $type      = "int";
            $plaintext = $value;
        }
        else {
            $type      = "float";
            $plaintext = $value;
        }
    }
    else {
        $type      = "str";
        $plaintext = $value;
    }

    my $gcm = Crypt::AuthEnc::GCM->new( "AES", $key, $iv );
    $gcm->adata_add($path);
    my $data = $gcm->encrypt_add($plaintext);
    my $tag  = $gcm->encrypt_done();

    return $class->new(
        data => $data,
        iv   => $iv,
        tag  => $tag,
        type => $type,
    );
}

1;

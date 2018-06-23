#!/usr/bin/perl

# This code make it easy to get started using OAuth 2.0 authorization to access the Gmail IMAP and SMTP services in Perl.
# Was inspired by OAuth 2.0 Libraries and Samples here: 
# https://developers.google.com/gmail/imap/xoauth2-libraries
# repo: https://github.com/google/gmail-oauth2-tools

use strict;
use warnings;
use Getopt::Long;
use Data::Dumper;
use Mojo::JSON qw/ decode_json /;
use Mojo::URL;
use Mojo::UserAgent;
use Mojo::Util qw/ b64_encode /;
use Mail::IMAPClient;
use Net::SMTP;
use Authen::SASL;

my %opts = (
    scope => 'https://mail.google.com/',
);
GetOptions(\%opts,
    'generate_oauth2_token',
    'poll_oauth2_token', # useless for gmail
    'generate_oauth2_string',
    'client_id=s',
    'client_secret=s',
    'access_token=s',
    'refresh_token=s',
    'scope=s',
    'test_imap_authentication',
    'test_smtp_authentication',
    'user=s',
#    'quiet',
    'help',
) or die("Error in command line arguments\n");

my $UA = Mojo::UserAgent->new;

if ($opts{generate_oauth2_token}) {
    required_opts(\%opts, 'client_id', 'client_secret');
    printf "To authorize token, visit this url:\n%s\n", generate_permission_url(\%opts);
    print "Enter verification code: ";
    my $auth_code = <STDIN>;
    chomp $auth_code;
    my $response = get_auth_token(\%opts, $auth_code);
    print_access_info($response);

}
elsif ($opts{poll_oauth2_token}) {
    warn "this doesn't provides a good gmail authorization token\n";
    required_opts(\%opts, 'client_id', 'client_secret');
    my $access_granted = oauth_for_devices(\%opts);
    print_access_info($access_granted);
}
elsif ($opts{generate_oauth2_string}) {
    required_opts(\%opts, 'user', 'access_token');
    printf "OAuth2 argument:\n%s\n", generate_oauth2_string(\%opts);
}
elsif ($opts{refresh_token}) {
    required_opts(\%opts, 'client_id', 'client_secret', 'refresh_token');
    my $refreshed = get_refreshed_token(\%opts);
    print_access_info($refreshed);
}
elsif ($opts{test_imap_authentication}) {
    required_opts(\%opts, 'user', 'access_token');
    my $oauth_sign = generate_oauth2_string(\%opts);
    test_imap($oauth_sign);
}
elsif ($opts{test_smtp_authentication}) {
    required_opts(\%opts, 'user', 'access_token');
    my $oauth_sign = generate_oauth2_string(\%opts);
    test_smtp($oauth_sign);
}
else {
    print_help();
}
exit 0;

sub print_access_info {
    my ($ref) = @_;
    print "\n";
    printf "Refresh Token: %s\n", $ref->{refresh_token} // '-';
    printf "Access Token: %s\n", $ref->{access_token};
    printf "Access Token Expiration Seconds: %d\n", $ref->{expires_in};
}

# https://developers.google.com/gmail/imap/xoauth2-protocol#imap_protocol_exchange
sub test_imap {
    my ($oauth_sign) = @_;
    my $server = 'imap.gmail.com';
    my $imap = Mail::IMAPClient->new(
        Server  => $server,
        Port    => 993,
        Ssl     => 1,
        Debug   => 1,
    ) or die('Can\'t connect to imap server.');
    $imap->authenticate('XOAUTH2', sub { return $oauth_sign })
        or die("Auth error: ". $imap->LastError);
    $imap->select('INBOX') or die "Could not select: $@\n";
}

# https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange
sub test_smtp {
    my ($oauth_sign) = @_;
    my $server = 'smtp.gmail.com';
    my $smtp = Net::SMTP->new($server,
        Port    => 587,
        SSL     => 0,
        Debug   => 1,
        Hello   => 'test',
    ) or die("Can't connect to smtp server. $@");
    $smtp->starttls();
    # manual enforcing with command. 
    # Authen::SASL and Net::SMTP doesn't work as expected (from me)
    $smtp->command('AUTH', 'XOAUTH2', $oauth_sign)->response();
    # following how it should be:
    # my $sasl = Authen::SASL->new(
    #     mechanism => 'XOAUTH2',
    #     callback => sub { return $oauth_sign; },
    # );
    # printf "DEBUG: %s\n", $smtp->supports('AUTH');
    # printf "DEBUG: %s\n", $sasl->mechanism();
    # $smtp->auth($sasl);
}

# https://developers.google.com/identity/protocols/OAuth2InstalledApp#offline
sub get_refreshed_token {
    my ($opt) = @_;
    my $client_id     = $opt->{client_id};
    my $client_secret = $opt->{client_secret};
    my $refresh_token = $opt->{refresh_token};
    my $url = Mojo::URL->new('https://www.googleapis.com/oauth2/v4/token');
    my $tx = $UA->post($url, {}, form => {
            client_id     => $client_id,
            client_secret => $client_secret,
            refresh_token => $refresh_token,
            grant_type    => 'refresh_token',
        });
    my $res = $tx->success;
    die "ERROR: ".Dumper($tx->error) if not $res;
    $res->json;
}

sub generate_oauth2_string {
    my ($opt) = @_;
    my $user = $opt->{user};
    my $access_token = $opt->{access_token};
    my $raw_auth_str = sprintf "user=%s\x01auth=Bearer %s\x01\x01", $user, $access_token;
    my $auth_str = b64_encode $raw_auth_str, '';
    return $auth_str;
}

# https://developers.google.com/accounts/docs/OAuth2InstalledApp
# returns URL that user should visit in browser
sub generate_permission_url {
    my ($opt) = @_;
    my $client_id     = $opt->{client_id};
    my $client_secret = $opt->{client_secret};
    my $url = Mojo::URL->new('https://accounts.google.com/o/oauth2/v2/auth');
    $url->query(
        client_id => $client_id,
        redirect_uri => 'urn:ietf:wg:oauth:2.0:oob',
        scope => 'https://mail.google.com',
        response_type => 'code',
    );
    return $url;
}

sub get_auth_token {
    my ($opt, $auth_code) = @_;
    my $client_id     = $opt->{client_id};
    my $client_secret = $opt->{client_secret};
    my $url = Mojo::URL->new('https://www.googleapis.com/oauth2/v4/token');
    my $tx = $UA->post($url, {}, form => {
            client_id     => $client_id,
            client_secret => $client_secret,
            code          => $auth_code,
            redirect_uri  => 'urn:ietf:wg:oauth:2.0:oob',
            grant_type    => 'authorization_code',
        });
    my $res = $tx->success;
    die "ERROR: ".Dumper($tx->error) if not $res;
    $res->json;
}

# https://developers.google.com/identity/protocols/OAuth2ForDevices
# OAuth 2.0 to access Google APIs via application on devices with no access to browser or limited input
# Credentials > OAuth client ID
# Step 4: Poll Google's authorization server
# Step 6: Handle polling response
# {
#   "access_token": "ya29...1Wc",
#   "token_type": "Bearer",
#   "expires_in": 3600,
#   "refresh_token": "1/3...f4",
#   "id_token": "eyJ...bA"
# }
# useless for gmail
sub oauth_for_devices {
    my ($opt) = @_;
    my $client_id     = $opt->{client_id};
    my $client_secret = $opt->{client_secret};
    my $device_data = get_device_data($client_id);

    # Step 3: Display user code
    printf "User code: '%s'\n", $device_data->{user_code};
    printf "Go here '%s' to verify the device with the code in %d min.\n", $device_data->{verification_url}, $device_data->{expires_in} / 60;

    my $now = time();
    my $url = Mojo::URL->new('https://www.googleapis.com/oauth2/v4/token');
    my ($tx, $res);
    while (1) {
        if (time() > $now + $device_data->{expires_in}) {
            die "device credentials expired\n";
        }

        $tx = $UA->post($url, {}, form => {
                client_id     => $client_id,
                client_secret => $client_secret,
                code          => $device_data->{device_code},
                grant_type    => 'http://oauth.net/grant_type/device/1.0',
            });
        $res = $tx->success;

        if (not $res) {
            # warn $tx->res->to_string();
            my $content = $tx->res->json;
            my $error = $content->{error};
            if ($error eq 'authorization_pending') {
                print STDERR "_";
            }
            elsif ($error eq 'slow_down') {
                print STDERR ".";
                sleep 1; # sleep 1 more sec
            }
            else {
                warn $tx->res->to_string();
                die "ERROR: ".Dumper($tx->error);
            }
            sleep $device_data->{interval};
            next;
        }
    
        last;
    }

    my $access_granted = $res->json;
    # warn Dumper $access_granted;
    return $access_granted;
}

# Step 1: Request device and user codes
# Step 2: Handle authorization response
# {
#     "device_code": "AH-...XQ",
#     "user_code": "P...-...H",
#     "expires_in": 1800,
#     "interval": 5,
#     "verification_url": "https://www.google.com/device"
# }
sub get_device_data {
    my ($client_id) = @_;

    my $url = Mojo::URL->new('https://accounts.google.com/o/oauth2/device/code');
    # scopes: Google Sign-In, Gmail API
    # ref: https://developers.google.com/identity/protocols/googlescopes
    my $tx = $UA->post($url, {}, form => {
            client_id => $client_id,
            scope => join(' ', 'email', 'profile'),
        });
    my $res = $tx->success;
    die "ERROR: ".Dumper($tx->error) if not $res;
    # warn $res->to_string;
    $res->json;
}

# test required options
sub required_opts {
    my ($opts, @required) = @_;
    for my $r (@required) {
        next if defined $opts->{$r};
        die "need '--$r' option\n";
    }
}

sub print_help {
    printf "Testing IMAP OAuth2 authentication\n";
    printf "Options:\n";
    printf " \t --generate_oauth2_token  \t generates OAuth2 token\n";
    printf " \t --generate_oauth2_string \t generates OAuth2 string\n";
    printf " \t --client_id <str>        \t \n";
    printf " \t --client_secret <str>    \t \n";
    printf " \t --access_token <str>     \t \n";
    printf " \t --user <str>             \t email address of user\n";
    printf " \t --refresh_token <str>    \t refresh the access token\n";
#    printf " \t --scope <str>            \t \n";
    printf " \t --test_imap_authentication \t Attempts to authenticate to IMAP\n";
    printf " \t --test_smtp_authentication \t Attempts to authenticate to SMTP\n";
#    printf " \t --quiet \t \n";
    printf " \t --help  \t \n";
    printf "\n";
    printf "Examples:\n";
    printf " 1. %s --user xxxgmail.com   --client_id aaa...apps.googleusercontent.com --client_secret xyz --generate_oauth2_token\n", $0;
    printf " 2. %s --user xxx\@gmail.com --client_id aaa...apps.googleusercontent.com --client_secret xyz --refresh_token 1/XYZ\n", $0;
    printf " 3. %s --user xxx\@gmail.com --access_token y29...Lg --generate_oauth2_string\n", $0;
    printf " 4. %s --user xxx\@gmail.com --access_token y29...Lg --test_smtp_authentication\n", $0;
}

__END__

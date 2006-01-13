package Authen::Simple::CDBI;

use strict;
use warnings;
use base 'Authen::Simple::Adapter';

use Params::Validate qw[];

our $VERSION = 0.1;

__PACKAGE__->options({
    class => {
        type     => Params::Validate::SCALAR,
        optional => 0
    },
    username => {
        type     => Params::Validate::SCALAR,
        default  => 'username',
        optional => 1
    },
    password => {
        type     => Params::Validate::SCALAR,
        default  => 'password',
        optional => 1
    }
});

sub check {
    my ( $self, $username, $password ) = @_;

    my $class    = $self->class;
    my $ucolumn  = $self->username;
    my $pcolumn  = $self->password;
    my $encryped = undef;

    unless ( eval "require $class;" ) {

        $self->log->error( qq/Failed to require class '$class'. Reason: '$@'/ )
          if $self->log;

        return 0;
    }

    unless ( $class->isa('Class::DBI') ) {

        $self->log->error( qq/Class '$class' is not a subclass of 'Class::DBI'./ )
          if $self->log;

        return 0;
    }

    unless ( $class->find_column($ucolumn) ) {

        $self->log->error( qq/Class '$class' does not have a username column named '$ucolumn'/ )
          if $self->log;

        return 0;
    }

    unless ( $class->find_column($pcolumn) ) {

        $self->log->error( qq/Class '$class' does not have a password column named '$pcolumn'/ )
          if $self->log;

        return 0;
    }

    my $user = $class->retrieve( $ucolumn => $username );

    unless ( defined $user ) {

        $self->log->debug( qq/User '$username' was not found with class '$class'./ )
          if $self->log;

        return 0;
    }

    unless ( defined( $encryped = $user->get($pcolumn) ) ) {

        $self->log->debug( qq/Encrypted password for user '$username' was not found with class '$class'./ )
          if $self->log;

        return 0;
    }

    unless ( $self->check_password( $password, $encryped ) ) {

        $self->log->debug( qq/Failed to authenticate user '$username'. Reason: 'Invalid credentials'/ )
          if $self->log;

        return 0;
    }

    $self->log->debug( qq/Successfully authenticated user '$username' with class '$class'./ )
      if $self->log;

    return 1;
}

1;

__END__

=head1 NAME

Authen::Simple::CDBI - Simple CDBI authentication

=head1 SYNOPSIS

    use Authen::Simple::CDBI;
    
    my $cdbi = Authen::Simple::DBI->new(
        class => 'MyApp::Model::User'
    );
    
    if ( $cdbi->authenticate( $username, $password ) ) {
        # successfull authentication
    }
    
    # or as a mod_perl Authen handler

    PerlModule Authen::Simple::Apache
    PerlModule Authen::Simple::CDBI

    PerlSetVar AuthenSimpleDBI_class "MyApp::Model::User"

    <Location /protected>
      PerlAuthenHandler Authen::Simple::CDBI
      AuthType          Basic
      AuthName          "Protected Area"
      Require           valid-user
    </Location>

=head1 DESCRIPTION

CDBI authentication.

=head1 METHODS

=over 4

=item * new

This method takes a hash of parameters. The following options are
valid:

=over 8

=item * class

Class::DBI subclass. Required.

    class => 'MyApp::Model::User'

=item * username

Name of C<username> column. Defaults to C<username>.

    username => 'username'
    
=item * password

Name of C<password> column. Defaults to C<password>.

    password => 'password'

=item * log

Any object that supports C<debug>, C<info>, C<error> and C<warn>.

    log => Log::Log4perl->get_logger('Authen::Simple::CDBI')

=back

=item * authenticate( $username, $password )

Returns true on success and false on failure.

=back

=head1 SEE ALSO

L<Authen::Simple>.

L<Authen::Simple::Password>.

L<Class::DBI>.

=head1 AUTHOR

Christian Hansen C<ch@ngmedia.com>

=head1 COPYRIGHT

This program is free software, you can redistribute it and/or modify 
it under the same terms as Perl itself.

=cut

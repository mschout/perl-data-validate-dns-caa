package Data::Validate::DNS::CAA;

# ABSTRACT: Validate DNS Certification Authority Authorization (CAA) values

use 5.010;
use strict;
use warnings;

use base 'Exporter';

use Syntax::Keyword::Junction qw(any);
use Data::Validate::URI qw(is_web_uri);
use Data::Validate::Email qw(is_email);
use Taint::Util qw(untaint);

our @EXPORT_OK = qw(
    is_caa_tag
    is_caa_value
    is_caa_issue
    is_caa_iodef
    is_caa_issuewild);

=method new()

Constructor

=cut

sub new {
    my $class = shift;
    return bless { @_ }, ref $class || $class;
}

=func is_caa_tag($value, %opts)

Returns the untainted tag if the value appears to be a valid CAA tag name as defined in RFC 6844.

C<%opts>, if present can contain the following:

=over 4

=item * strict

Default: 1

In this mode, the tag must match exactly one of the registered tag names in RFC
6844, or the IANA registry for CAA tag names.  Note that reserved tags are not
allowed.  Turning this off will merely do a syntax check on the tag string.

=back

=cut

sub is_caa_tag {
    my ($self, $value, %opts) = _maybe_oo(@_);

    unless (defined $opts{strict}) {
        $opts{strict} = 1;
    }

    if ($opts{strict}) {
        # strict mode, only allow registered tag names
        if (lc $value eq any(qw(issue issuewild iodef))) {
            untaint($value);

            return $value;
        }
    }
    else {
        # just a syntax check
        unless ($value =~ /[^a-zA-Z0-9]/) {
            untaint($value);

            return $value;
        }
    }

    return;
}

=func is_caa_value($tagname, $value)

Returns the untainted value if it appears to be a valid CAA tag name/value pair.

=cut

sub is_caa_value {
    my ($self, $tag, $value) = _maybe_oo(@_);

    $tag = lc $tag;

    if ($tag eq 'issue') {
        return is_caa_issue($value);
    }
    elsif ($tag eq 'issuewild') {
        return is_caa_issue($value);
    }
    elsif ($tag eq 'iodef') {
        return is_caa_iodef($value);
    }

    return;
}

=func is_caa_issue($value)

Returns the untainted value if it looks like a CAA issue (or issuewild) value.

=cut

sub is_caa_issue {
    my ($self, $value) = _maybe_oo(@_);

    # match using grammar from RFC 6844
    my $issue_re = qr{
        (?&issueval)
        (?(DEFINE)
            (?<issueval>    \s* (?&domain)? \s* (?&tagstring)? )
            (?<domain>      (?&label) (?: . (?&label) )* )
            (?<label>       [0-9a-zA-Z] (?: \-* [0-9A-Za-z] )* )
            (?<tagstring>   ; (?: \s* (?&parameter) )* \s* )
            (?<parameter>   [0-9A-Za-z]+ = [\x21-\x7e]* )
        )
    }x;

    if ($value =~ qr/^$issue_re$/) {
        untaint($value);

        return $value;
    }

    return;
}

=func is_caa_issuewild($value)

Returns the untainted value if it looks like a CAA issuewild value.  Since
issuewild values have the same syntax as issue values, this is identical to
C<is_caa_issue()>.

=cut

sub is_caa_issuewild {
    return is_caa_issue(@_);
}

=func is_caa_iodef($value)

Returns the untainted value if it looks like a CAA iodef value.

=cut

sub is_caa_iodef {
    my ($self, $value) = _maybe_oo(@_);

    # handle http/https uris
    if (is_web_uri($value)) {
        untaint($value);

        return $value;
    }

    if (lc $value =~ /^mailto:\S+@\S+/) {
        $value =~ s/^mailto://;

        if (is_email($value)) {
            untaint($value);

            return $value;
        }
    }

    return;
}

sub _maybe_oo {
    my $self = shift if ref $_[0];

    return ($self, @_);
}

1;

__END__

=head1 SYNOPSIS

 use Data::Validate::DNS::CAA qw(is_issue is_issuewild is_iodef);

 if (is_caa_tag('issue')) {
    print "Looks like a CAA tag value\n";
 }
 else {
    print "Not a CAA tag value\n";
 }

 if (is_caa_value(issue => 'ca.example.com; policy=ev')) {
     print "Looks like a CAA issue value\n";
 }
 else {
     print "Not a CAA issue value\n";
 }

 if (is_caa_value(iodef => 'mailto:security@example.com')) {
     print "Looks like a CAA iodef value\n";
 }
 else {
     print "Not a CAA iodef value\n";
 }

 # or use Object interface.

 my $v = Data::Validate::CAA::DNS->new;

 die "not a CAA tag value" unless $v->is_caa_tag($suspect);


=head1 DESCRIPTION

This module offers a few subroutines for validating DNS Certification Authority
Authorization (CAA) record fields to make input validation and untainting
easier and more readable.

All of the functions return an untainted value on success and a false value
(undef or empty list) on failure.  In scalar context you should check that the
return value is defined.

All functions can be called as methods if using the object oriented interface.

=head1 SEE ALSO

RFC 6844

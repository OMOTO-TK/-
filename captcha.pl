#!/usr/bin/perl

use CGI::Carp qw(fatalsToBrowser);

use strict;

use CGI;
use DBI;

use lib '.';
BEGIN { require "config.pl"; }
BEGIN { require "config_defaults.pl"; }
BEGIN { require "strings_en.pl"; }
BEGIN { require "wakautils.pl"; }



return 1 if(caller);

my $font_height=8;
my %font=(
	'1'=>[2,[1,1,1,6],[-1,2,1,1]],
	'0'=>[3,[0,4,1,2,2,2,3,3,3,5,2,6,1,6,0,5,0,4]],
	'2'=>[3,[-1,3,1,1,3,1],[3,1,0,5],[0,5,5,5]],
	'3'=>[3,[-1,3,1,1,3,1],[3,1,1,4],[1,4,3,5],[3,5,-1,7],[-1,7]],
	'4'=>[3,[0,0,0,3],[0,3,4,3],[4,3,4,0],[4,3,4,8]],
	'5'=>[3,[5,0,0,0],[0,0,0,2],[0,2,3,2],[3,2,3,6],[3,6,0,6]],
	'6'=>[3,[5,0,4,1,3,2,2,3,1,4],[1,4,0,5,0,6,3,6,3,5,1,4]],
	'7'=>[3,[0,0,6,0],[6,0,0,6]],
	'8'=>[3,[0,4,1,3,2,3,3,4,3,5,2,6,1,6,0,5,0,4],[1,3,2,3,3,3,3,2,2,0,1,0,0,2,0,3,1,3]],
	'9'=>[3,[1,3,2,3,3,3,3,2,2,0,1,0,0,2,0,3,1,3],[3,3,0,7]],
	' '=>[3],
);


my $query=new CGI;
my $key=($query->param("key") or 'default');
my $selector=($query->param("selector") or ".captcha");
my $style=($query->cookie("wakabastyle") or DEFAULT_STYLE);

my @foreground=find_stylesheet_color($style,$selector);
my @background=(0xff,0xff,0xff);



my $dbh=DBI->connect(SQL_DBI_SOURCE,SQL_USERNAME,SQL_PASSWORD,{AutoCommit=>1}) or die S_SQLCONF;
init_captcha_database($dbh) unless(table_exists_captcha($dbh,SQL_CAPTCHA_TABLE));

my $ip=($ENV{REMOTE_ADDR} or '0.0.0.0');
my ($word,$timestamp)=get_captcha_word($dbh,$ip,$key);

if(!$word)
{
	$word=make_word();
	$timestamp=time();
	save_captcha_word($dbh,$ip,$key,$word,$timestamp);
}

srand $timestamp;



print $query->header(
	-type=>'image/gif',
#	-expires=>'+'.($timestamp+(CAPTCHA_LIFETIME)-time()),
#	-expires=>'now',
);

binmode STDOUT;

make_image($word);

#
# End of main code
#



#
# Code generation
#

sub make_word()
{
	my %grammar=(
		W => ["%A%%B%%C%%D%%E%%F%"],
		A => ['0','1','2','3','4','5','6','7','8','9'],
		B => ['1','0','2','3','4','5','6','7','8','9'],
		C => ['1','2','0','3','4','5','6','7','8','9'],
		D => ['1','2','0','3','4','5','6','7','8','9'],
		E => ['1','2','0','3','4','5','6','7','8','9'],
		F => ['1','2','0','3','4','5','6','7','8','9'],
		

	);

	return cfg_expand("%W%",%grammar);
}

sub get_captcha_key($)
{
	my ($parent)=@_;

	return 'res'.$parent if($parent);
	return 'mainpage';
}



#
# Finding and saving words
#

sub get_captcha_word($$$)
{
	my ($dbh,$ip,$key)=@_;
	my ($sth,$row);

	$sth=$dbh->prepare("SELECT word,timestamp FROM ".SQL_CAPTCHA_TABLE." WHERE ip=? AND pagekey=?;") or return undef;
	$sth->execute($ip,$key) or return undef; # the captcha script creates the database, so it might not exist yet
	return @{$row} if($row=$sth->fetchrow_arrayref());

	return undef;
}

sub save_captcha_word($$$$$)
{
	my ($dbh,$ip,$key,$word,$time)=@_;

	delete_captcha_word($dbh,$ip,$key);

	my $sth=$dbh->prepare("INSERT INTO ".SQL_CAPTCHA_TABLE." VALUES(?,?,?,?);") or die S_SQLFAIL;
	$sth->execute($ip,$key,$word,$time) or die S_SQLFAIL;

	trim_captcha_database($dbh); # only cleans up on create - good idea or not?
}

sub check_captcha($$$$)
{
	my ($dbh,$captcha,$ip,$parent)=@_;

	my $key=get_captcha_key($parent);
	my ($word)=get_captcha_word($dbh,$ip,$key);

	make_error(S_NOCAPTCHA) unless($word);
    if($word ne lc($captcha))
    {
        delete_captcha_word($dbh,$ip,$key);
        make_error(S_BADCAPTCHA);
    }
	
	delete_captcha_word($dbh,$ip,$key);
	   
	

	 
}

sub delete_captcha_word($$$)
{
	my ($dbh,$ip,$key)=@_;

	my $sth=$dbh->prepare("DELETE FROM ".SQL_CAPTCHA_TABLE." WHERE ip=? AND pagekey=?;") or return;
	$sth->execute($ip,$key) or return;
}



#
# Database utils
#

sub init_captcha_database($)
{
	my ($dbh)=@_;
	my ($sth);

	$sth=$dbh->do("DROP TABLE ".SQL_CAPTCHA_TABLE.";") if(table_exists_captcha($dbh,SQL_CAPTCHA_TABLE));
	$sth=$dbh->prepare("CREATE TABLE ".SQL_CAPTCHA_TABLE." (".
	"ip TEXT,".
	"pagekey TEXT,".
	"word TEXT,".
	"timestamp INTEGER".
#	",PRIMARY KEY(ip,key)".
	");") or die S_SQLFAIL;
	$sth->execute() or die S_SQLFAIL;
}

sub trim_captcha_database($)
{
	my ($dbh)=@_;
	my $mintime=time()-(CAPTCHA_LIFETIME);

	my $sth=$dbh->prepare("DELETE FROM ".SQL_CAPTCHA_TABLE." WHERE timestamp<=$mintime;") or die S_SQLFAIL;
	$sth->execute() or die S_SQLFAIL;
}

sub table_exists_captcha($$)
{
	my ($dbh,$table)=@_;
	my ($sth);

	return 0 unless($sth=$dbh->prepare("SELECT * FROM ".$table." LIMIT 1;"));
	return 0 unless($sth->execute());
	return 1;
}



#
# Stylesheet functions
#

sub find_stylesheet_color($$)
{
	my ($style,$selector)=@_;

	my ($sheet)=grep
	{
		my ($title)=m!([^/]+)\.css$!i;
		$title=ucfirst $title;
		$title=~s/_/ /g;
		$title=~s/ ([a-z])/ \u$1/g;
		$title=~s/([a-z])([A-Z])/$1 $2/g;
		$title eq $style;
	} glob(CSS_DIR."*.css");
	return (128,0,0) unless($sheet);

	my $contents;
	open STYLESHEET,$sheet or return (128,0,0);
	$contents.=$_ while(<STYLESHEET>);
	close STYLESHEET;

	if($contents=~/(?:}|^)\s+\Q$selector\E\s*{[^}]*color:\s*([^;}]+?)\s*(?:;|}|^)/s)
	{
		my $color=$1;
		if($color=~/#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/i)
		{
			return (hex($1),hex($2),hex($3));
		}
		elsif($color=~/#([0-9a-f])([0-9a-f])([0-9a-f])/i)
		{
			return (hex($1x2),hex($2x2),hex($3x2));
		}
		elsif($color=~/rgb\s*\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)/)
		{
			return ($1,$2,$3);
		}
	}
	return (128,0,0);
}



#
# Draw the actual image
#

my (@pixels,$pixel_w,$pixel_h);

sub make_image($)
{
	my ($word)=@_;
	my ($width,$height);

	$pixel_w=$width;
	$pixel_h=$height;

	draw_string($word);

	my $height=@pixels;
	my $width=max (map { $_?scalar(@{$_}):0 } @pixels);

	start_128_gif($width,$height,@background,@foreground);
	for(my $y=0;$y<$height;$y++) { emit_pixel_block($pixels[$y],$width); }
	end_gif();
}

sub max(@)
{
	my $max=pop @_;
	$max=$_>$max?$_:$max for(@_);
	return $max;
}

sub emit_pixel_block($$)
{
	my ($pixels,$num)=@_;
	for(my $i=0;$i<$num;$i++) { emit_gif_pixel($$pixels[$i]); }
}



#
# String drawing
#

my ($scale,$rot,$dx,$dy);

sub draw_string($)
{
	my @chars=split //,$_[0];
	my $x_offs=int(CAPTCHA_HEIGHT/$font_height*2);

	foreach my $char (@chars)
	{
		next unless($font{$char});
		my ($char_w,@strokes)=@{$font{$char}};

		setup_transform($char_w);

		foreach my $stroke (@strokes)
		{
			my @coords=@{$stroke};
			my ($prev_x,$prev_y);

			($prev_x,$prev_y)=transform_coords(shift @coords,shift @coords);

			while(@coords)
			{
				my ($x,$y);
				($x,$y)=transform_coords(shift @coords,shift @coords);

				draw_line($prev_x+$x_offs,$prev_y,$x+$x_offs,$y,1);
				draw_line(0,5,$x+$x_offs,5,1);
				draw_line(0,10,$x+$x_offs,10,1);

				$prev_x=$x;
				$prev_y=$y;
			}
		}
		$x_offs+=int(($char_w+(CAPTCHA_SPACING))*$scale);
	
	}
}

sub setup_transform($)
{
	my ($char_w)=@_;

	$dx=$char_w/2;
	$dy=$font_height/2;
	$scale=CAPTCHA_HEIGHT/$font_height*(1+(CAPTCHA_SCALING)*(1-rand(2)));
	$rot=(rand(2)-1)*(CAPTCHA_ROTATION);
}

sub transform_coords($$)
{
	my ($x,$y)=@_;

	return (
		int($scale*(cos($rot)*($x-$dx)-sin($rot)*($y-$dy)+$dx+rand(CAPTCHA_SCRIBBLE))),
		int($scale*(sin($rot)*($x-$dx)+cos($rot)*($y-$dy)+$dy+rand(CAPTCHA_SCRIBBLE)))
	);
}

sub draw_line($$$$$)
{
	my ($x1,$y1,$x2,$y2,$col)=@_;
	my ($x,$y,$i,$dx,$dy,$l,$m,$x_inc,$y_inc,$err,$dx2,$dy2);

	$x=$x1; $y=$y1;
	$dx=$x2-$x1; $dy=$y2-$y1;
	$x_inc=($dx<0)?-1:1; $l=$dx*$x_inc;
	$y_inc=($dy<0)?-1:1; $m=$dy*$y_inc;
	$dx2=$l*2; $dy2=$m*2;

	if($l>=$m)
	{
		$err=$dy2-$l;
		for($i=0;$i<$l;$i++)
		{
			draw_pixel($x,$y,$col);
			if($err>0)
			{
				$y+=$y_inc;
				$err-=$dx2;
			}
			$err+=$dy2;
			$x+=$x_inc;
		}
	}
	else
	{
		$err=$dx2-$m;
		for($i=0;$i<$m;$i++)
		{
			draw_pixel($x,$y,$col);
			if($err>0)
			{
				$x+=$x_inc;
				$err-=$dy2;
			}
			$err+=$dx2;
			$y+=$y_inc;
		}
	}
	draw_pixel($x,$y,$col);
}

sub draw_pixel($$$)
{
	my ($x,$y,$col)=@_;

	return if($x<0 or $y<0);

	$pixels[$y][$x]=$col;
	$pixels[$y][$x+1]=$col;
}



#
# GIF generation
#

my ($pixels,$block);

sub start_128_gif($$@)
{
	my ($width,$height,@palette)=@_;
	$pixels=0;
	$block='';

	print pack("A6 vv CCC","GIF89a",$width,$height,0xa6,0,0);
	print pack('CCC'x128,@palette);
	print pack('CCC CvCC',0x21,0xf9,4,0x01,0,0,0);
	print pack('CvvvvCC',0x2c,0,0,$width,$height,0x00,0x07);
}

sub start_128_grey_gif($$@)
{
	my ($width,$height,@palette)=@_;
	$pixels=0;
	$block='';

	print pack("A6 vv CCC","GIF87a",$width,$height,0xa6,0,0);
	for(my $i=0;$i<64;$i++) { print pack('CCC',$i*2,$i*2,$i*2); }
	for(my $i=64;$i<128;$i++) { print pack('CCC',$i*2+1,$i*2+1,$i*2+1); }
	print pack('CvvvvCC',0x2c,0,0,$width,$height,0x00,0x07);
}

sub emit_gif_pixel($)
{
	my ($pixel)=@_;

	emit_gif_byte(0x80) if(($pixels%126)==0);
	emit_gif_byte($pixel);
	$pixels++;
}

sub emit_gif_byte($)
{
	my ($byte)=@_;

	$block.=pack('C',$byte);

	if(length($block)==255)
	{
		print pack('C',255);
		print $block;
		$block='';
	}
}

sub end_gif()
{
	emit_gif_byte(0x81);
	emit_gif_byte(0);

	if($block)
	{
		print pack('C',length($block));
		print $block;
	}
	print pack('C',';');
}

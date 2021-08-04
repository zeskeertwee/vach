#![allow(unused_variables)]
use std::{fs::File, io::{BufReader, Read}, str};

fn main(){
	let file = File::open("me.vach").unwrap();
	let mut reader = BufReader::new(file);
	let mut buffer = [0;5];

	reader.read(&mut buffer).unwrap();
	let magic = String::from(str::from_utf8(&buffer).unwrap());
	
	match magic == "VfACH" {
		 true => println!("That over there is some mighty fine archive file"),
		 false => println!("Invalid archive file")
	};
}
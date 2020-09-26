#!/usr/bin/node
const readline = require('readline');
const fs = require('fs');
const rl = readline.createInterface({
	input: process.stdin,
	terminal: true,
	output: process.stdout
});
rl.question('> ', (answer) => {
	var blah = eval((function (st){ return st.replace(/[^![\]\(\)!+-]/g, ''); })(answer));
	if (blah == "Let me out"){
		fs.readFile("flag.txt", 'utf8', function(err, data) {
			if (err) throw err;
			console.log(data)
		});
	}
	rl.close();
});

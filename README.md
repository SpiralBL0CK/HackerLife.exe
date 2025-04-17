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

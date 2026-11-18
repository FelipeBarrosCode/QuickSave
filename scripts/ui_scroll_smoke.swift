// SPDX-License-Identifier: GPL-3.0-only
// Synthetic UI-only acceptance in an isolated WebKit data store. No native
// command, keychain, provider account, or user filesystem is exposed to the page.
import AppKit
import Foundation
import WebKit

let fixture = #"""
(() => {
  globalThis.isTauri = true;
  const providers = [
    {id:'fixture-provider',name:'Synthetic test storage — '.repeat(8),kind:'s3',status:'connected',origin:'quicksave',readOnly:false}
  ];
  const software = Array.from({length:80}, (_,i) => ({
    id:`fixture-software-${i}`,appId:`fixture:${i}`,name:`Synthetic application ${i} — ` + 'VeryLongName'.repeat(12),
    tracked:true,providerId:'fixture-provider',status:i%2?'saved':'needs_backup',autosave:false,
    fileCount:100,logicalBytes:1048576,dirty:i%2===0
  }));
  const bundles = Array.from({length:25},(_,i) => ({
    id:`fixture-bundle-${i}`,appId:`fixture:${i}`,name:`Synthetic bundle ${i} — `+'LongCloudBundle'.repeat(15),
    providerId:'fixture-provider',fileCount:100,logicalBytes:1048576,format:'No Land',platform:'linux'
  }));
  const files = Array.from({length:100},(_,i) => ({
    id:`root/save-${i}.dat`,name:`Save ${i}.dat`,path:'synthetic/'.repeat(28)+`save-${i}.dat`,
    directory:false,size:1024,rootId:'root'
  }));
  const activity = [{id:'fixture-upload',kind:'upload',name:'Synthetic upload — '+'LongActivityName'.repeat(12),
    state:'running',completedBytes:123,totalBytes:1000,canCancel:true,canRetry:false}];
  globalThis.__TAURI_INTERNALS__ = {invoke:async(command,args) => {
    if(command!=='workspace_query') throw Error('UI smoke forbids native mutations and dialogs');
    switch(args.query) {
      case 'dashboard': return {providers,software,activity,summary:{needsBackup:40,autosaveEnabled:0,connectedProviders:1}};
      case 'provider_types': return {providerTypes:[{kind:'s3',name:'S3 test provider',auth:'credentials',
        fields:[{name:'access_key_id',label:'Access key ID',required:true,secret:true,type:'password'}]}]};
      case 'software': return {software};
      case 'activity': return {activity};
      case 'operation': return activity[0];
      case 'bundles': return {bundles,nextCursor:null};
      case 'software_files': case 'bundle_files': return {files,nextCursor:'fixture-page-2'};
      default: throw Error('Unexpected synthetic query');
    }
  }};
})();
"""#

let probe = #"""
const waitFor = predicate => new Promise((resolve,reject) => {
  if(predicate()) return resolve();
  const observer = new MutationObserver(() => { if(predicate()){observer.disconnect();resolve();} });
  observer.observe(document.documentElement,{subtree:true,childList:true,attributes:true});
});
const settle = () => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
const find = name => [...document.querySelectorAll('button,a')].find(element => element.textContent.trim()===name);
await waitFor(() => find('Backup') && document.querySelector('main'));
const results = [];
for(const page of ['Overview','Backup','Restore']){
  find(page).click();
  await settle();
  if(page==='Backup') {
    await waitFor(() => document.body.textContent.includes('Synthetic application 0'));
    document.querySelector('.software-name')?.click();
    await waitFor(() => document.querySelectorAll('.file-row').length===100);
  }
  if(page==='Restore') {
    document.querySelector('.provider-card')?.click();
    await waitFor(() => document.querySelector('.bundle-choice'));
    document.querySelector('.bundle-choice').click();
    await settle();
    find('Browse individual files')?.click();
    await waitFor(() => document.querySelectorAll('.file-row').length===100);
  }
  await settle();
  const root = document.documentElement, body = document.body;
  const main = document.querySelector('.main-scroll') ?? document.querySelector('main');
  const scrolls = [...document.querySelectorAll('*')].filter(element => {
    const style = getComputedStyle(element);
    return ['auto','scroll'].includes(style.overflowY) && element.scrollHeight>element.clientHeight+1;
  });
  const before = main.scrollTop;
  if(main.scrollHeight>main.clientHeight+1) main.scrollTop=Math.min(120,main.scrollHeight-main.clientHeight);
  await settle();
  const result = {
    page,width:innerWidth,height:innerHeight,documentWidth:root.scrollWidth,bodyWidth:body.scrollWidth,
    mainWidth:main.clientWidth,mainScrollHeight:main.scrollHeight,mainHeight:main.clientHeight,
    rootScrollHeight:root.scrollHeight,rootOverflow:getComputedStyle(root).overflowY,
    rootScrollable:root.scrollHeight>innerHeight+1&&!['hidden','clip'].includes(getComputedStyle(root).overflowY),
    rootScrollTop:root.scrollTop,windowScrollY:scrollY,
    sidebarTop:document.querySelector('aside')?.getBoundingClientRect().top,
    transferLabelsFit:page!=='Backup'||[...document.querySelectorAll('.software-row > .button')]
      .every(button=>button.getBoundingClientRect().height<=50&&button.scrollWidth<=button.clientWidth+1),
    scrollContainers:scrolls.map(element=>({tag:element.tagName,className:element.className})),
    horizontalOverflow:root.scrollWidth>innerWidth+1||body.scrollWidth>innerWidth+1,
    mainScrollWorked:main.scrollHeight<=main.clientHeight+1||main.scrollTop>before||before>0
  };
  results.push(result);
}
find('Overview').click();
await settle();
const main=document.querySelector('.main-scroll');
main.scrollTop=50;
const priorScroll=main.scrollTop,priorWidth=main.clientWidth;
find('Connect providers').click();
await waitFor(() => document.querySelector('[role="dialog"]'));
await settle();
const dialog=document.querySelector('[role="dialog"]');
const modal={width:innerWidth,mainScrollPreserved:main.scrollTop===priorScroll,
  mainWidthPreserved:main.clientWidth===priorWidth,
  horizontalOverflow:document.documentElement.scrollWidth>innerWidth+1
    ||dialog.scrollWidth>dialog.clientWidth+1};
dialog.querySelector('.dialog-header button').click();
await settle();
const aside = document.querySelector('aside');
const navigation = aside ? [...aside.querySelectorAll('nav button,nav a')].map(element=>element.textContent.trim()) : [];
return {results,navigation,modal};
"""#

final class Navigation: NSObject, WKNavigationDelegate {
    var ready: CheckedContinuation<Void, Error>?
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        ready?.resume(); ready = nil
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        ready?.resume(throwing: error); ready = nil
    }
}

let application = NSApplication.shared
application.setActivationPolicy(.accessory)
let configuration = WKWebViewConfiguration()
configuration.websiteDataStore = .nonPersistent()
configuration.userContentController.addUserScript(WKUserScript(source:fixture,injectionTime:.atDocumentStart,forMainFrameOnly:true))
let webView = WKWebView(frame:NSRect(x:0,y:0,width:1320,height:900),configuration:configuration)
webView.autoresizingMask = [.width,.height]
let navigation = Navigation()
webView.navigationDelegate = navigation
let window = NSWindow(contentRect:webView.frame,styleMask:[.titled,.closable,.resizable],backing:.buffered,defer:false)
window.title = "QuickSave — isolated synthetic UI check"
window.contentView = webView
window.makeKeyAndOrderFront(nil)

// One deadline, not a polling loop. The harness never presses a real native
// permission dialog: its fake IPC explicitly rejects all mutation requests.
DispatchQueue.main.asyncAfter(deadline:.now()+60) {
    fputs("WebKit UI smoke deadline exceeded\n",stderr)
    exit(1)
}
Task { @MainActor in
    do {
        let url = URL(string:CommandLine.arguments.dropFirst().first ?? "http://127.0.0.1:1420")!
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            navigation.ready = continuation
            webView.load(URLRequest(url:url))
        }
        var receipts:[[String:Any]] = []
        for (width,height) in [(1320,900),(880,680),(360,740)] {
            window.setContentSize(NSSize(width:width,height:height))
            let value = try await webView.callAsyncJavaScript(probe,arguments:[:],in:nil,contentWorld:.page)
            guard let receipt = value as? [String:Any], let results = receipt["results"] as? [[String:Any]] else {
                throw NSError(domain:"QuickSaveUISmoke",code:1,userInfo:[NSLocalizedDescriptionKey:"Invalid WebKit result"])
            }
            for result in results {
                guard result["horizontalOverflow"] as? Bool == false,
                      result["rootScrollable"] as? Bool == false,
                      result["mainScrollWorked"] as? Bool == true,
                      result["rootScrollTop"] as? Int == 0,
                      result["windowScrollY"] as? Int == 0,
                      result["sidebarTop"] as? Int == 0,
                      result["transferLabelsFit"] as? Bool == true else {
                    throw NSError(domain:"QuickSaveUISmoke",code:2,userInfo:[NSLocalizedDescriptionKey:"Unstable scroll geometry: \(result)"])
                }
            }
            guard let modal = receipt["modal"] as? [String:Any],
                  modal["mainScrollPreserved"] as? Bool == true,
                  modal["mainWidthPreserved"] as? Bool == true,
                  modal["horizontalOverflow"] as? Bool == false,
                  receipt["navigation"] as? [String] == ["Overview","Backup","Restore"] else {
                throw NSError(domain:"QuickSaveUISmoke",code:3,userInfo:[NSLocalizedDescriptionKey:"Modal/navigation geometry changed: \(receipt)"])
            }
            receipts.append(receipt)
            if width == 1320 {
                for page in ["Overview","Backup"] {
                    _ = try await webView.callAsyncJavaScript(
                        "const button=[...document.querySelectorAll('nav button')].find(button=>button.textContent.trim()===page);button.click();await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return true;",
                        arguments:["page":page],in:nil,contentWorld:.page)
                    let image = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<NSImage,Error>) in
                        webView.takeSnapshot(with:nil) { image,error in
                            if let image { continuation.resume(returning:image) }
                            else { continuation.resume(throwing:error ?? NSError(domain:"QuickSaveUISmoke",code:4)) }
                        }
                    }
                    if let tiff=image.tiffRepresentation, let bitmap=NSBitmapImageRep(data:tiff),
                       let png=bitmap.representation(using:.png,properties:[:]) {
                        try png.write(to:URL(fileURLWithPath:"artifacts/workspace-v2-\(page.lowercased()).png"))
                    }
                }
            }
        }
        let output = try JSONSerialization.data(withJSONObject:["syntheticOnly":true,"engine":"WKWebView","viewports":receipts],options:[.prettyPrinted,.sortedKeys])
        FileHandle.standardOutput.write(output)
        FileHandle.standardOutput.write(Data("\n".utf8))
        window.orderOut(nil)
        exit(0)
    } catch {
        fputs("WebKit UI smoke failed: \(error)\n",stderr)
        exit(1)
    }
}
application.run()

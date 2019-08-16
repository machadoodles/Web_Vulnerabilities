---


---

<h1 id="owasp-top-10---a-primer">OWASP Top 10 - A Primer</h1>
<p>This document explores the 10 vulnerability classes discussed in <a href="https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf">OWASP Top 10 - 2017</a>.</p>
<h2 id="vulnerabilities">Vulnerabilities</h2>
<h3 id="a32017---sensitive-data-exposure">A3:2017 - Sensitive Data Exposure</h3>
<blockquote>
<p>The exposure of sensitive data has become one of the most common sought after avenues for attacks over the past few years, begging with unencrypted data being transmitted. Poorly encrypted data can easily be revealed with GPU password cracking tools and other mechanisms to reverse the engineer algorithms and at times not even using simple cryptography principals. More sophisticated bad actors can be very effective while executing man-in-the-middle-attacks, steal crypto keys and even install software to steal key presses installed on client machines or directly off the server.</p>
</blockquote>
<ul>
<li>What kind of damage it can do to a business</li>
</ul>
<blockquote>
<p>Personal information can be intercepted and then used to siphon out capital. Best and easiest solution would be to not hold any of the sensitive data. 3rd party services can be outsourced to carry this load and are extremely efficient at serving that purpose. They encrypt credit card info, while connecting directly to merchants and by passing much of the heavy lifting.</p>
</blockquote>
<h4 id="how-it-works">How it Works</h4>
<p><strong>Local File Inclusion (LFI)</strong>,Sensitive Data Exposure vulnerability.</p>
<blockquote>
<p>This vulnerability occurs, for example, when a page receives, as input, the path to the file that has to be included and this input is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash) to be injected. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.</p>
</blockquote>
<h4 id="scenario">Scenario</h4>
<p>Specifically, explain</p>
<ul>
<li>How you perform the attack
<ul>
<li><code>http://127.0.0.1/dvwa/vulnerabilities/fi/?page=../../../../../../../etc/passwd</code><br>
<img src="https://drive.google.com/file/d/1aqOvV135D2xzWj19SOMPfK9hu1u2VUJN/view?usp=sharing" alt="DVWA injected"></li>
</ul>
</li>
<li>This works are there aren’t any route-guards to protect from wandering users.</li>
<li>Some type of route-guards can be configured giving users a 404 page.</li>
</ul>
<div class="mermaid"><svg xmlns="http://www.w3.org/2000/svg" id="mermaid-svg-ykGNapcOadCJUphp" width="100%" style="max-width: 514.2703094482422px;" viewBox="0 0 514.2703094482422 169.0984344482422"><g transform="translate(-12, -12)"><g class="output"><g class="clusters"></g><g class="edgePaths"><g class="edgePath" style="opacity: 1;"><path class="path" d="M72.59375,83.78955548874876L146.171875,48.088279724121094L243.5390625,48.088279724121094" marker-end="url(#arrowhead2339)" style="fill:none"></path><defs><marker id="arrowhead2339" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" class="arrowheadPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></path></marker></defs></g><g class="edgePath" style="opacity: 1;"><path class="path" d="M72.59375,109.30887895949343L146.171875,145.0101547241211L219.75,145.0101547241211" marker-end="url(#arrowhead2340)" style="fill:none"></path><defs><marker id="arrowhead2340" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" class="arrowheadPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></path></marker></defs></g><g class="edgePath" style="opacity: 1;"><path class="path" d="M291.3828125,48.088279724121094L340.171875,48.088279724121094L390.40118078163965,72.31991296836037" marker-end="url(#arrowhead2341)" style="fill:none"></path><defs><marker id="arrowhead2341" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto"><path d="M 0 0 L 0 0 L 0 0 z" style="fill: #333"></path></marker></defs></g><g class="edgePath" style="opacity: 1;"><path class="path" d="M315.171875,145.0101547241211L340.171875,145.0101547241211L390.40117871575535,121.77852246575539" marker-end="url(#arrowhead2342)" style="fill:none"></path><defs><marker id="arrowhead2342" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" class="arrowheadPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></path></marker></defs></g></g><g class="edgeLabels"><g class="edgeLabel" style="opacity: 1;" transform="translate(146.171875,48.088279724121094)"><g transform="translate(-48.578125,-13)" class="label"><foreignObject width="97.15625" height="26"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;"><span class="edgeLabel">Modified URL</span></div></foreignObject></g></g><g class="edgeLabel" style="opacity: 1;" transform=""><g transform="translate(0,0)" class="label"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;"><span class="edgeLabel"></span></div></foreignObject></g></g><g class="edgeLabel" style="opacity: 1;" transform=""><g transform="translate(0,0)" class="label"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;"><span class="edgeLabel"></span></div></foreignObject></g></g><g class="edgeLabel" style="opacity: 1;" transform=""><g transform="translate(0,0)" class="label"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;"><span class="edgeLabel"></span></div></foreignObject></g></g></g><g class="nodes"><g class="node" style="opacity: 1;" id="A" transform="translate(46.296875,96.5492172241211)"><rect rx="0" ry="0" x="-26.296875" y="-23" width="52.59375" height="46"></rect><g class="label" transform="translate(0,0)"><g transform="translate(-16.296875,-13)"><foreignObject width="32.59375" height="26"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;">User</div></foreignObject></g></g></g><g class="node" style="opacity: 1;" id="B" transform="translate(267.4609375,48.088279724121094)"><circle x="-23.921875" y="-23" r="23.921875"></circle><g class="label" transform="translate(0,0)"><g transform="translate(-13.921875,-13)"><foreignObject width="27.84375" height="26"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;">404</div></foreignObject></g></g></g><g class="node" style="opacity: 1;" id="C" transform="translate(267.4609375,145.0101547241211)"><rect rx="5" ry="5" x="-47.7109375" y="-23" width="95.421875" height="46"></rect><g class="label" transform="translate(0,0)"><g transform="translate(-37.7109375,-13)"><foreignObject width="75.421875" height="26"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;">Login page</div></foreignObject></g></g></g><g class="node" style="opacity: 1;" id="D" transform="translate(441.7210922241211,96.5492172241211)"><polygon points="76.54921875000001,0 153.09843750000002,-76.54921875000001 76.54921875000001,-153.09843750000002 0,-76.54921875000001" rx="5" ry="5" transform="translate(-76.54921875000001,76.54921875000001)"></polygon><g class="label" transform="translate(0,0)"><g transform="translate(-52.0546875,-13)"><foreignObject width="104.109375" height="26"><div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;">Welcome Page</div></foreignObject></g></g></g></g></g></g></svg></div>
<blockquote>
<ul>
<li><a href="https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion">https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion</a></li>
<li><a href="https://angular.io/guide/router">https://angular.io/guide/router</a></li>
</ul>
</blockquote>
<hr>
<h3 id="a42017---xml-external-entities-xxe">A4:2017 - XML External Entities (XXE)</h3>
<h5 id="the-source-severity-and-scope-of-xxe-attacks">The source, severity, and scope of XXE attacks</h5>
<blockquote>
<p>This vulnerability occurs when an attacker has the ability to exploit XML processors, usually this happens when it is possible to upload XML or if hostile content is included within an XML document. While easy to detect, XXE vulnerabilities are not as prevelant as other examples on the OWASP list.</p>
</blockquote>
<h5 id="what-kind-of-damage-it-can-do-to-a-business">What kind of damage it can do to a business</h5>
<blockquote>
<p>XXE vulnerabilities can be used to extract data, execute remote requests, scan internal systems, perform DoS attacks, etc.</p>
</blockquote>
<h4 id="how-it-works-1">How it Works</h4>
<h5 id="what-xml-is">What XML is</h5>
<blockquote>
<p>XML is a markup language similar to HTML, though it places a larger focus on transfering data rather than only displaying DOM elements.</p>
</blockquote>
<h5 id="how-web-applications-use-xml">How web applications use XML</h5>
<blockquote>
<p>XML is sent via an API (application processing interface) and received then parsed to be manipulated or displayed on another application.</p>
</blockquote>
<h5 id="why-web-applications-can-be-attacked-via-xml-uploads">Why web applications can be attacked via XML uploads</h5>
<blockquote>
<p>XML features can be abused to carry out DoS attacks, access logical files, generate unauthorized connections to outside networks, or circumvent firewalls.</p>
</blockquote>
<h5 id="ways-that-xxe-payloads-can-be-delivered">Ways that XXE payloads can be delivered</h5>
<blockquote>
<p>XXE expansion occurs when XML input containing a reference to an outside entity is processed by a weakly configured XML parser.</p>
</blockquote>
<h4 id="scenario-1">Scenario</h4>
<p>Here’s an explanation as to how XXE works in the following examples</p>
<h5 id="payload-1">Payload 1</h5>
<pre class=" language-xml"><code class="prism  language-xml"><span class="token prolog">&lt;?xml version="1.0" encoding="ISO-8859-1"?&gt;</span> <span class="token doctype">&lt;!DOCTYPE foo [
&lt;!ELEMENT foo ANY &gt;</span>
&lt;!ENTITY xxe SYSTEM "file:///etc/passwd" &gt;]&gt; <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>foo</span><span class="token punctuation">&gt;</span></span><span class="token entity" title="&amp;xxe;">&amp;xxe;</span><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>foo</span><span class="token punctuation">&gt;</span></span>
</code></pre>
<blockquote>
<p>This payload is targeting the site’s PASSWORD (passwd) folder and  calling it to display its content when the ‘foo’ array is called. This hides a command it the XML making it hard to detect.</p>
</blockquote>
<h5 id="payload-2">Payload 2</h5>
<pre class=" language-xml"><code class="prism  language-xml">&lt;!ENTITY xxe SYSTEM "https://192.168.1.1/private" &gt;]&gt;
</code></pre>
<blockquote>
<p>Here this XML is calling on the server’s private network by changing the ENTITY line.</p>
</blockquote>
<h5 id="payload-3">Payload 3</h5>
<pre class=" language-xml"><code class="prism  language-xml">&lt;!ENTITY xxe SYSTEM "file:///dev/random" &gt;]&gt;
</code></pre>
<blockquote>
<p>This is an example of an attacker trying to set a Denial-of-Service attack by including a potentially endless file</p>
</blockquote>
<blockquote>
<ul>
<li>src = “<a href="https://resources.infosecinstitute.com/2017-owasp-a4-update-xml-external-entities-xxe/">https://resources.infosecinstitute.com/2017-owasp-a4-update-xml-external-entities-xxe/</a>”</li>
</ul>
</blockquote>
<hr>
<h3 id="a52017---broken-access-control">A5:2017 - Broken Access Control</h3>
<h4 id="definition--description">Definition / Description</h4>
<p>TODO: Use the OWASP document to explain</p>
<ul>
<li>The source, scope, and severity of broken access control vulnerabilities</li>
</ul>
<blockquote>
<p>To uncover Broken Access Control vulnerabilities, tools such as SAST and DAST may be used. While these tools reveal absence of access controls, manual work is needed to determine if the vulnerability is functional. These types of vulnerabilities are common due to lack of automated detection, though this also means it takes time for attackers to uncover the vulnerabilities as well.</p>
</blockquote>
<ul>
<li>What kind of damage it can do to a business</li>
</ul>
<blockquote>
<p>Successful exploitation can allow attackers to act as users/admins, allowing the possibility of creating, accessing, updating, and deleting records.</p>
</blockquote>
<h4 id="how-it-works-2">How it Works</h4>
<p>TODO: Explain why LFI also qualifies as a Broken Access Control vulnerability!</p>
<blockquote>
<p>Once a flaw is discovered, the consequences of a flawed access control scheme can be devastating. In addition to viewing unauthorized content, an attacker might be able to change or delete content, perform unauthorized functions, or even take over site administration.</p>
<ul>
<li>src=“<a href="https://www.owasp.org/index.php/Broken_Access_Control">https://www.owasp.org/index.php/Broken_Access_Control</a>”</li>
</ul>
</blockquote>
<h4 id="scenario-2">Scenario</h4>
<p>Suppose you log into an application as the user <code>jane</code>, and get redirected to: <code>https://example.site/userProfile.php?user=jane</code>.</p>
<p>Suppose Jane is able to see Bob’s profile by navigating to: <code>https://example.site/userProfile.php?user=bob</code></p>
<ul>
<li>This is called <strong>Insecure Direct Object Reference (IDOR)</strong> Read about it here: <a href="https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)">https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)</a>.</li>
</ul>
<hr>
<h3 id="a82017---insecure-deserialization">A8:2017 - Insecure Deserialization</h3>
<h4 id="definition--description-1">Definition / Description</h4>
<h5 id="what-serialization-is">What serialization is</h5>
<blockquote>
<p><strong>Serialization</strong> is a process of converting an Object into stream of bytes to then be transferred over a network or stored in storage. Serialized objects are converted into a binary format or structured text.</p>
</blockquote>
<h5 id="what-deserialization-is">What deserialization is</h5>
<blockquote>
<p><strong>Deserialization</strong> is the exact opposite - Fetch a stream of bytes from network or persistence storage and convert it back to the Object <strong>with the same state</strong>.</p>
</blockquote>
<h5 id="what-web-applications-use-serializationdeserialization-for">What web applications use serialization/deserialization for</h5>
<ul>
<li>What kinds of attacks can be carried out by exploiting insecure deserialization bugs</li>
</ul>
<h4 id="how-it-works--scenario">How it Works / Scenario</h4>
<blockquote>
<p>Code injection or Remote Code Execution (RCE) enables the attacker to execute malicious code as a result of an injection attack. Code Injection attacks are different than Command Injection attacks.</p>
<ul>
<li>src <a href="https://www.acunetix.com/blog/articles/what-is-insecure-deserialization/">Acutenix article</a></li>
</ul>
</blockquote>
<h3 id="a92017---using-components-with-known-vulnerabilities">A9:2017 - Using Components with Known Vulnerabilities</h3>
<blockquote>
<p>While it is easy to find already-written exploits for many known vulnerabilities, other vulnerabilities require concentrated effort to develop a custom exploit.</p>
</blockquote>
<h4 id="how-it-works-3">How it Works</h4>
<blockquote>
<p>Supply Chain Risk is a very delicate issue as one link is so dependent to the rest of the operation. If one is misguided and gets hacked, everyone else may be vaulnerable.</p>
</blockquote>
<h4 id="scenario-3">Scenario</h4>
<blockquote>
<p>Node Package Manager is servered thousands of times a day. Serving corrupt code can affect many computers very quickly. This could have carried out malitious code and bricked many machines.</p>
</blockquote>
<h3 id="a102017---insufficient-logging--monitoring">A10:2017 - Insufficient Logging &amp; Monitoring</h3>
<blockquote>
<p>Exploitation of insufficient logging and monitoring is the bedrock of nearly every major incident.</p>
</blockquote>
<h4 id="how-it-works--scenario-1">How it Works / Scenario</h4>
<blockquote>
<p>Lock out a user’s account to defend against Brute Force attacks. Auditable events, such as logins, failed logins, and high-value transactions are not logged.</p>
</blockquote>

<table>
<thead>
<tr>
<th></th>
<th>Dangers</th>
<th>Remedy</th>
</tr>
</thead>
<tbody>
<tr>
<td>XXE</td>
<td><code>Extract data, remotely executed</code></td>
<td>JSON data parsers</td>
</tr>
<tr>
<td>LFI</td>
<td><code>Exposes local file's content</code></td>
<td>Configured Route-guards</td>
</tr>
<tr>
<td>Logging &amp; Motoring</td>
<td><code>Sessions may be hijacked</code></td>
<td>Set up session timeout feature</td>
</tr>
</tbody>
</table>

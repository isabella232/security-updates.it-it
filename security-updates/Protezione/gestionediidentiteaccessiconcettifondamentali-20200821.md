---
TOCTitle: 'Gestione di identità e accessi: Concetti fondamentali'
Title: 'Gestione di identità e accessi: Concetti fondamentali'
ms:assetid: '660a4fa3-4e21-43d2-9583-9fcb019d99da'
ms:contentKeyID: 20200821
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Dd536221(v=TechNet.10)'
---

Concetti fondamentali
=====================

### Riconoscimenti

Aggiornato: 29 aprile 2004

Microsoft Solutions for Security (MSS) desidera ringraziare le persone direttamente responsabili o che hanno dato un significativo contributo alla stesura e alla revisione del presente documento della *Serie Microsoft Gestione di identità e accessi*.

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Team di sviluppo</p></th>
<th><p> </p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p><strong>Autori ed esperti</strong></p></td>
<td style="border:1px solid black;"><p><strong>Tester</strong></p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>David Mowers, MSS</p></td>
<td style="border:1px solid black;"><p>Gaurav Singh Bora, Infosys Technologies</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Michel Baladi, Microsoft Services</p></td>
<td style="border:1px solid black;"><p>Prathiraj Chakka, Infosys Technologies</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Paige Verwolf, Microsoft Services</p></td>
<td style="border:1px solid black;"><p>Mehul Mediwala, Infosys Technologies</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Anthony Steven, Content Master Ltd</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p><strong>Redattori</strong></p></td>
<td style="border:1px solid black;"><p><strong>Responsabile di programma</strong></p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>John Cobb, Volt Information Sciences</p></td>
<td style="border:1px solid black;"><p>Derick Campbell, MSS</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Steve Wacker, Volt Information Sciences</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><strong>Altri collaboratori e revisori di versioni beta</strong></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p><strong>Microsoft</strong></p></td>
<td style="border:1px solid black;"><p><strong>Collaboratori esterni</strong></p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Stefan Richards, Windows Security</p></td>
<td style="border:1px solid black;"><p>Patrick O'Kane, ePresence Inc.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Jenn Goth, Microsoft Services</p></td>
<td style="border:1px solid black;"><p>Eran Feigenbaum, Pricewaterhouse Coopers LLP</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Brian Fielder, Microsoft Services</p></td>
<td style="border:1px solid black;"><p>Rosa Caputo, Blockade Systems</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Brian Redmond, Microsoft Services</p></td>
<td style="border:1px solid black;"><p>James Cowling, Oxford Computing Group</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Kannan C. Iyer, Directory Services</p></td>
<td style="border:1px solid black;"><p>Frank Kaleck, Comma Soft AG</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Craig Martin, Microsoft Services</p></td>
<td style="border:1px solid black;"><p>Matthias Marburger, Comma Soft AG</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Robert Ginsburg, Version3 Inc.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Thomas J. Schenkman, Goldman Sachs</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Jørgen D. Holm, KMD</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Kyle Young, Oblix Inc.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Ken Jeras, Oblix Inc.</p></td>
</tr>  
</tbody>  
</table>
  
[](#mainsection)[Inizio pagina](#mainsection)

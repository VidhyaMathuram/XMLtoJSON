# XMLtoJSON
Parse Xml to Json
Reads particular Tags from a XML file.
Find number of header(detail tag) tags for iteration.
Group cve tag based upon the severity of Risk tag. 
Take count of cve.
Take count of each Risk severity.
Here the Risk is asumed as Low(0,1 risk), Medium(2,3), and high(4,5).
Take count of Portnumber tag and its corresponding values.
Take count of hostname tag and its corresponding values.
All the counts are put into JSON Object.
All the corresponding values are put into Json Aray which is again put into JSON object.
Output file is created or appended according to the status and output is written at the end of each Header(here it is detail tag) tag.

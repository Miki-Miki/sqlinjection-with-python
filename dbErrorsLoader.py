from xml.dom import minidom

xmlDoc = minidom.parse('errors.xml')
dbErrors = xmlDoc.getElementsByTagName('error')
errors = []

for items in dbErrors: 
    errors.append(items.attributes['regexp'].value)


print(errors)
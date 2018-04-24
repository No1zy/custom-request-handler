# custom-request-handler
This extension is customized for "Rule Actoins" in "Session Handling Rules".

## It was possible
* Automaticaly overwrites JSON and Headers with handled request from macro function.
* You can config a simple list of string that are used as payloads.

# Instlation
Jython 2.7+ is required for this extension to work to set it up in Burp's Extender Options before adding the extension. 

# User guide - How to use?
### Standard settings.
1. Click Project options > Sessions > Session Handling Rules > add.
2. Setting macros.
3. Select After running the macro. invoke a Burp extension handler.
4. Select "custom request handler" from dropdown menu.
5. click "OK".

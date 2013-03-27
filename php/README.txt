Useful PHP5 code for generating/handling Payment messages.

Relies on Protobuf-PHP for reading/writing protocol buffer encoded files:
  http://drslump.github.com/Protobuf-PHP/
See that website for installation instructions.

paymentrequest.php was generated from the paymentrequest.proto file by running the
protoc-gen-php tool in the directory above this one, like this:

  protoc-gen-php -o php -i $(pwd) paymentrequest.proto


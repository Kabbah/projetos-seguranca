# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ServiceResponse.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ServiceResponse.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  serialized_pb=_b('\n\x15ServiceResponse.proto\"#\n\x0fServiceResponse\x12\x10\n\x08response\x18\x01 \x02(\x0c')
)




_SERVICERESPONSE = _descriptor.Descriptor(
  name='ServiceResponse',
  full_name='ServiceResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='response', full_name='ServiceResponse.response', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=25,
  serialized_end=60,
)

DESCRIPTOR.message_types_by_name['ServiceResponse'] = _SERVICERESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ServiceResponse = _reflection.GeneratedProtocolMessageType('ServiceResponse', (_message.Message,), dict(
  DESCRIPTOR = _SERVICERESPONSE,
  __module__ = 'ServiceResponse_pb2'
  # @@protoc_insertion_point(class_scope:ServiceResponse)
  ))
_sym_db.RegisterMessage(ServiceResponse)


# @@protoc_insertion_point(module_scope)
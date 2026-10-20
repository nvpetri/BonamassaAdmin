// Contrato das chaves estrangeiras da API 0.13.1; as views não possuem FKs próprias.
export const relations = [
  ['User',['storeId'],'Store',['id']],
  ['Product',['storeId'],'Store',['id']],
  ['Product',['storeId','imageId'],'ProductImage',['storeId','id']],
  ['ProductImage',['storeId'],'Store',['id']],
  ['Promotion',['storeId'],'Store',['id']],
  ['Quote',['storeId','userId'],'User',['storeId','id']],
  ['Order',['storeId','quoteId'],'Quote',['storeId','id']],
  ['Order',['storeId','customerId'],'User',['storeId','id']],
  ['Order',['storeId','driverId'],'User',['storeId','id']],
  ['Order',['storeId','promotionId'],'Promotion',['storeId','id']],
  ['OrderEvent',['orderId'],'Order',['id']],
  ['Session',['userId'],'User',['id']],
  ['VerificationCode',['userId'],'User',['id']],
  ['StaffInvitation',['userId'],'User',['id']],
  ['Idempotency',['storeId','userId'],'User',['storeId','id']],
  ['Audit',['storeId'],'Store',['id']]
];

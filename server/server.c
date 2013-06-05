#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void *tmp;

void take_data_pointers_backup(SSL_CTX *ctx)
{
	//Open File for backup
    FILE *fp;
    fp = fopen("d_backup","w");
    
	fprintf(fp,"%ld\n",ctx->method);
	fprintf(fp,"%ld\n",ctx->cipher_list);
	fprintf(fp,"%ld\n",ctx->cipher_list_by_id);
	fprintf(fp,"%ld\n",ctx->cert_store);
	fprintf(fp,"%ld\n",ctx->cert_store->objs);
	/*fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->skid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->akid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->akid->keyid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->akid->serial);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->valid_policy);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->valid_policy->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->valid_policy->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.cpsuri);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.usernotice);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.usernotice->noticeref);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.usernotice->noticeref->organization);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.usernotice->noticeref->noticenos);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.usernotice->exptext);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->qualifier_set->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->expected_policy_set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->expected_policy_set->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->anyPolicy->expected_policy_set->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->valid_policy);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->valid_policy->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->valid_policy->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.cpsuri);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.usernotice);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.usernotice->noticeref);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.usernotice->noticeref->organization);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.usernotice->noticeref->noticenos);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.usernotice->exptext);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->qualifier_set->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->expected_policy_set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->expected_policy_set->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->policy_cache->data->expected_policy_set->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.fullname->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.relativename);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.relativename->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.relativename->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.relativename->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->distpoint->name.relativename->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->reasons);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->crldp->CRLissuer->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->altname->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->base->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->minimum);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->permittedSubtrees->maximum);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->base->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->minimum);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->nc->excludedSubtrees->maximum);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->trust);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->trust->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->trust->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->reject);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->reject->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->reject->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->alias);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->keyid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->algorithm);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->algorithm->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->algorithm->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->x509->aux->other->parameter->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->version);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->algorithm);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->algorithm->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->algorithm->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->sig_alg->parameter->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->issuer->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->lastUpdate);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->nextUpdate);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->revoked);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->revoked->serialNumber);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->revoked->revocationDate);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->extensions);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->extensions->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->extensions->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->extensions->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl->extensions->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->algorithm);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->algorithm->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->algorithm->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->sig_alg->parameter->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->signature);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->keyid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->issuer->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->akid->serial);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.fullname->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relativename);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relativename->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relativename->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relativename->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relativename->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relative->dpname);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relative->dpname->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relative->dpname->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relative->dpname->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relative->dpname->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.relative->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->distpoint->name.bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->idp->onlysomereasons);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->crl_number);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->base_crl_number);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->type_id);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->type_id->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->type_id->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.otherName->value->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.rfc822Name);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dNSName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.x400Address->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.directoryName->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.ediPartyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.ediPartyName->nameAssigner);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.ediPartyName->partyName);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.uniformResourceIdentifier);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.iPAddress);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.registeredID);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.registeredID->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.registeredID->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.ip);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn->entries);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn->entries->object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn->entries->object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn->entries->object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn->entries->value);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.dirn->bytes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.ia5);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.rid);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.rid->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.rid->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->crl->issuers->d.other->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->ameth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->rsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->dsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->dh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->ecdh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->ecdsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->store_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->cmd_defns);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->prev);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->engine->next);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->rsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->dsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->dh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->ecdh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->ecdsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->store_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->cmd_defns);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->prev);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->engine->next);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->n);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->e);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d->p);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d->p->q);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d->p->q->dmp1);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d->p->q->dmp1->dmq1);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d->p->q->dmp1->dmq1->iqmp);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->d->p->q->dmp1->dmq1->iqmp->_method_mo->_method_mo->_method_mo->bignum_->blinding);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.rsa->mt_blinding);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->p);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->q);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->g);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->pub_key);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->priv_key);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->kinv);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->r);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->rsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->dsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->dh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->ecdh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->ecdsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->store_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->cmd_defns);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->prev);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dsa->engine->next);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->p);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->g);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->pub_key);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->priv_key);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->q);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->j);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->counter);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->rsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->dsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->dh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->ecdh_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->ecdsa_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->store_meth);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->cmd_defns);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->prev);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.dh->engine->next);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->group);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->group->generator);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->group->extra_data);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->group->extra_data->next);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->pub_key);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->priv_key);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->method_data);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->pkey.ec->method_data->next);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.set->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.asn1_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.object);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.object->sn);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.object->ln);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.integer);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.enumerated);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.bit_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.octet_string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.printablestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.t61string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.ia5string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.generalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.bmpstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.universalstring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.utctime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.generalizedtime);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.visiblestring);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.utf8string);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.set);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->data.ptr->pkey->attributes->value.single->value.sequence);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->get_cert_methods);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->get_cert_methods->method);
	fprintf(fp,"%ld\n",ctx->cert_store->objs->get_cert_methods->store_ctx);*/
	fprintf(fp,"%ld\n",ctx->app_verify_arg);
	fprintf(fp,"%ld\n",ctx->default_passwd_callback_userdata);
	fprintf(fp,"%ld\n",ctx->rsa_md5);
	fprintf(fp,"%ld\n",ctx->md5);
	fprintf(fp,"%ld\n",ctx->sha1);
	fprintf(fp,"%ld\n",ctx->msg_callback_arg);
	fprintf(fp,"%ld\n",ctx->param);
	/*fprintf(fp,"%ld\n",ctx->param->name->policies);
	fprintf(fp,"%ld\n",ctx->param->name->policies->sn);
	fprintf(fp,"%ld\n",ctx->param->name->policies->ln);*/
	fprintf(fp,"%ld\n",ctx->tlsext_servername_arg);
	fprintf(fp,"%ld\n",ctx->tlsext_status_arg);
	fprintf(fp,"%ld\n",ctx->tlsext_opaque_prf_input_callback_arg);
	fprintf(fp,"%ld\n",ctx->psk_identity_hint);
	fprintf(fp,"%ld\n",ctx->wbuf_freelist);
	/*fprintf(fp,"%ld\n",ctx->wbuf_freelist->head);
	fprintf(fp,"%ld\n",ctx->wbuf_freelist->head->next);*/
	fprintf(fp,"%ld\n",ctx->rbuf_freelist);
	/*fprintf(fp,"%ld\n",ctx->rbuf_freelist->head);
	fprintf(fp,"%ld\n",ctx->rbuf_freelist->head->next);*/
	fprintf(fp,"%ld\n",ctx->next_protos_advertised_cb_arg);
	fprintf(fp,"%ld\n",ctx->next_proto_select_cb_arg);
	
	//Close the file
	fclose(fp);
}

void take_function_pointers_backup(SSL_CTX *ctx) 
{
	//Open File for backup
    FILE *fp;
    fp = fopen("backup","w");
    
	if(ctx->method->ssl_new != 0) 
 	 fprintf(fp,"ssl_new %lx\n",(void*)ctx->method->ssl_new-tmp);
	else 
		 fprintf(fp,"ssl_new 0\n");
	if(ctx->method->ssl_clear != 0) 
		 fprintf(fp,"ssl_clear %lx\n",(void*)ctx->method->ssl_clear-tmp);
	else 
		 fprintf(fp,"ssl_clear 0\n");
	if(ctx->method->ssl_free != 0) 
		 fprintf(fp,"ssl_free %lx\n",(void*)ctx->method->ssl_free-tmp);
	else 
		 fprintf(fp,"ssl_free 0\n");
	if(ctx->method->ssl_accept != 0) 
		 fprintf(fp,"ssl_accept %lx\n",(void*)ctx->method->ssl_accept-tmp);
	else 
		 fprintf(fp,"ssl_accept 0\n");
	if(ctx->method->ssl_connect != 0) 
		 fprintf(fp,"ssl_connect %lx\n",(void*)ctx->method->ssl_connect-tmp);
	else 
		 fprintf(fp,"ssl_connect 0\n");
	if(ctx->method->ssl_read != 0) 
		 fprintf(fp,"ssl_read %lx\n",(void*)ctx->method->ssl_read-tmp);
	else 
		 fprintf(fp,"ssl_read 0\n");
	if(ctx->method->ssl_peek != 0) 
		 fprintf(fp,"ssl_peek %lx\n",(void*)ctx->method->ssl_peek-tmp);
	else 
		 fprintf(fp,"ssl_peek 0\n");
	if(ctx->method->ssl_write != 0) 
		 fprintf(fp,"ssl_write %lx\n",(void*)ctx->method->ssl_write-tmp);
	else 
		 fprintf(fp,"ssl_write 0\n");
	if(ctx->method->ssl_shutdown != 0) 
		 fprintf(fp,"ssl_shutdown %lx\n",(void*)ctx->method->ssl_shutdown-tmp);
	else 
		 fprintf(fp,"ssl_shutdown 0\n");
	if(ctx->method->ssl_renegotiate != 0) 
		 fprintf(fp,"ssl_renegotiate %lx\n",(void*)ctx->method->ssl_renegotiate-tmp);
	else 
		 fprintf(fp,"ssl_renegotiate 0\n");
	if(ctx->method->ssl_renegotiate_check != 0) 
		 fprintf(fp,"ssl_renegotiate_check %lx\n",(void*)ctx->method->ssl_renegotiate_check-tmp);
	else 
		 fprintf(fp,"ssl_renegotiate_check 0\n");
	if(ctx->method->ssl_get_message != 0) 
		 fprintf(fp,"ssl_get_message %lx\n",(void*)ctx->method->ssl_get_message-tmp);
	else 
		 fprintf(fp,"ssl_get_message 0\n");
	if(ctx->method->ssl_read_bytes != 0) 
		 fprintf(fp,"ssl_read_bytes %lx\n",(void*)ctx->method->ssl_read_bytes-tmp);
	else 
		 fprintf(fp,"ssl_read_bytes 0\n");
	if(ctx->method->ssl_write_bytes != 0) 
		 fprintf(fp,"ssl_write_bytes %lx\n",(void*)ctx->method->ssl_write_bytes-tmp);
	else 
		 fprintf(fp,"ssl_write_bytes 0\n");
	if(ctx->method->ssl_dispatch_alert != 0) 
		 fprintf(fp,"ssl_dispatch_alert %lx\n",(void*)ctx->method->ssl_dispatch_alert-tmp);
	else 
		 fprintf(fp,"ssl_dispatch_alert 0\n");
	if(ctx->method->ssl_ctrl != 0) 
		 fprintf(fp,"ssl_ctrl %lx\n",(void*)ctx->method->ssl_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_ctrl 0\n");
	if(ctx->method->ssl_ctx_ctrl != 0) 
		 fprintf(fp,"ssl_ctx_ctrl %lx\n",(void*)ctx->method->ssl_ctx_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_ctx_ctrl 0\n");
	if(ctx->method->get_cipher_by_char != 0) 
		 fprintf(fp,"get_cipher_by_char %lx\n",(void*)ctx->method->get_cipher_by_char-tmp);
	else 
		 fprintf(fp,"get_cipher_by_char 0\n");
	if(ctx->method->put_cipher_by_char != 0) 
		 fprintf(fp,"put_cipher_by_char %lx\n",(void*)ctx->method->put_cipher_by_char-tmp);
	else 
		 fprintf(fp,"put_cipher_by_char 0\n");
	if(ctx->method->ssl_pending != 0) 
		 fprintf(fp,"ssl_pending %lx\n",(void*)ctx->method->ssl_pending-tmp);
	else 
		 fprintf(fp,"ssl_pending 0\n");
	if(ctx->method->num_ciphers != 0) 
		 fprintf(fp,"num_ciphers %lx\n",(void*)ctx->method->num_ciphers-tmp);
	else 
		 fprintf(fp,"num_ciphers 0\n");
	if(ctx->method->get_cipher != 0) 
		 fprintf(fp,"get_cipher %lx\n",(void*)ctx->method->get_cipher-tmp);
	else 
		 fprintf(fp,"get_cipher 0\n");
	if(ctx->method->get_ssl_method != 0) 
		 fprintf(fp,"get_ssl_method %lx\n",(void*)ctx->method->get_ssl_method-tmp);
	else 
		 fprintf(fp,"get_ssl_method 0\n");
	if(ctx->method->get_timeout != 0) 
		 fprintf(fp,"get_timeout %lx\n",(void*)ctx->method->get_timeout-tmp);
	else 
		 fprintf(fp,"get_timeout 0\n");
	if(ctx->method->ssl_version != 0) 
		 fprintf(fp,"ssl_version %lx\n",(void*)ctx->method->ssl_version-tmp);
	else 
		 fprintf(fp,"ssl_version 0\n");
	if(ctx->method->ssl_callback_ctrl != 0) 
		 fprintf(fp,"ssl_callback_ctrl %lx\n",(void*)ctx->method->ssl_callback_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_callback_ctrl 0\n");
	if(ctx->method->ssl_ctx_callback_ctrl != 0) 
		 fprintf(fp,"ssl_ctx_callback_ctrl %lx\n",(void*)ctx->method->ssl_ctx_callback_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_ctx_callback_ctrl 0\n");
	if(ctx->cert_store->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->cert_store->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->cert_store->verify_cb != 0) 
		 fprintf(fp,"verify_cb %lx\n",(void*)ctx->cert_store->verify_cb-tmp);
	else 
		 fprintf(fp,"verify_cb 0\n");
	if(ctx->cert_store->get_issuer != 0) 
		 fprintf(fp,"get_issuer %lx\n",(void*)ctx->cert_store->get_issuer-tmp);
	else 
		 fprintf(fp,"get_issuer 0\n");
	if(ctx->cert_store->check_issued != 0) 
		 fprintf(fp,"check_issued %lx\n",(void*)ctx->cert_store->check_issued-tmp);
	else 
		 fprintf(fp,"check_issued 0\n");
	if(ctx->cert_store->check_revocation != 0) 
		 fprintf(fp,"check_revocation %lx\n",(void*)ctx->cert_store->check_revocation-tmp);
	else 
		 fprintf(fp,"check_revocation 0\n");
	if(ctx->cert_store->get_crl != 0) 
		 fprintf(fp,"get_crl %lx\n",(void*)ctx->cert_store->get_crl-tmp);
	else 
		 fprintf(fp,"get_crl 0\n");
	if(ctx->cert_store->check_crl != 0) 
		 fprintf(fp,"check_crl %lx\n",(void*)ctx->cert_store->check_crl-tmp);
	else 
		 fprintf(fp,"check_crl 0\n");
	if(ctx->cert_store->cert_crl != 0) 
		 fprintf(fp,"cert_crl %lx\n",(void*)ctx->cert_store->cert_crl-tmp);
	else 
		 fprintf(fp,"cert_crl 0\n");
	if(ctx->cert_store->lookup_certs != 0) 
		 fprintf(fp,"lookup_certs %lx\n",(void*)ctx->cert_store->lookup_certs-tmp);
	else 
		 fprintf(fp,"lookup_certs 0\n");
	if(ctx->cert_store->lookup_crls != 0) 
		 fprintf(fp,"lookup_crls %lx\n",(void*)ctx->cert_store->lookup_crls-tmp);
	else 
		 fprintf(fp,"lookup_crls 0\n");
	if(ctx->cert_store->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->cert_store->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->new_session_cb != 0) 
		 fprintf(fp,"new_session_cb %lx\n",(void*)ctx->new_session_cb-tmp);
	else 
		 fprintf(fp,"new_session_cb 0\n");
	if(ctx->remove_session_cb != 0) 
		 fprintf(fp,"remove_session_cb %lx\n",(void*)ctx->remove_session_cb-tmp);
	else 
		 fprintf(fp,"remove_session_cb 0\n");
	if(ctx->get_session_cb != 0) 
		 fprintf(fp,"get_session_cb %lx\n",(void*)ctx->get_session_cb-tmp);
	else 
		 fprintf(fp,"get_session_cb 0\n");
	if(ctx->app_verify_callback != 0) 
		 fprintf(fp,"app_verify_callback %lx\n",(void*)ctx->app_verify_callback-tmp);
	else 
		 fprintf(fp,"app_verify_callback 0\n");
	if(ctx->client_cert_cb != 0) 
		 fprintf(fp,"client_cert_cb %lx\n",(void*)ctx->client_cert_cb-tmp);
	else 
		 fprintf(fp,"client_cert_cb 0\n");
	if(ctx->app_gen_cookie_cb != 0) 
		 fprintf(fp,"app_gen_cookie_cb %lx\n",(void*)ctx->app_gen_cookie_cb-tmp);
	else 
		 fprintf(fp,"app_gen_cookie_cb 0\n");
	if(ctx->app_verify_cookie_cb != 0) 
		 fprintf(fp,"app_verify_cookie_cb %lx\n",(void*)ctx->app_verify_cookie_cb-tmp);
	else 
		 fprintf(fp,"app_verify_cookie_cb 0\n");
	if(ctx->rsa_md5->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->rsa_md5->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->rsa_md5->update != 0) 
		 fprintf(fp,"update %lx\n",(void*)ctx->rsa_md5->update-tmp);
	else 
		 fprintf(fp,"update 0\n");
	if(ctx->rsa_md5->final != 0) 
		 fprintf(fp,"final %lx\n",(void*)ctx->rsa_md5->final-tmp);
	else 
		 fprintf(fp,"final 0\n");
	if(ctx->rsa_md5->copy != 0) 
		 fprintf(fp,"copy %lx\n",(void*)ctx->rsa_md5->copy-tmp);
	else 
		 fprintf(fp,"copy 0\n");
	if(ctx->rsa_md5->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->rsa_md5->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->rsa_md5->sign != 0) 
		 fprintf(fp,"sign %lx\n",(void*)ctx->rsa_md5->sign-tmp);
	else 
		 fprintf(fp,"sign 0\n");
	if(ctx->rsa_md5->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->rsa_md5->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->rsa_md5->md_ctrl != 0) 
		 fprintf(fp,"md_ctrl %lx\n",(void*)ctx->rsa_md5->md_ctrl-tmp);
	else 
		 fprintf(fp,"md_ctrl 0\n");
	if(ctx->md5->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->md5->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->md5->update != 0) 
		 fprintf(fp,"update %lx\n",(void*)ctx->md5->update-tmp);
	else 
		 fprintf(fp,"update 0\n");
	if(ctx->md5->final != 0) 
		 fprintf(fp,"final %lx\n",(void*)ctx->md5->final-tmp);
	else 
		 fprintf(fp,"final 0\n");
	if(ctx->md5->copy != 0) 
		 fprintf(fp,"copy %lx\n",(void*)ctx->md5->copy-tmp);
	else 
		 fprintf(fp,"copy 0\n");
	if(ctx->md5->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->md5->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->md5->sign != 0) 
		 fprintf(fp,"sign %lx\n",(void*)ctx->md5->sign-tmp);
	else 
		 fprintf(fp,"sign 0\n");
	if(ctx->md5->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->md5->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->md5->md_ctrl != 0) 
		 fprintf(fp,"md_ctrl %lx\n",(void*)ctx->md5->md_ctrl-tmp);
	else 
		 fprintf(fp,"md_ctrl 0\n");
	if(ctx->sha1->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->sha1->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->sha1->update != 0) 
		 fprintf(fp,"update %lx\n",(void*)ctx->sha1->update-tmp);
	else 
		 fprintf(fp,"update 0\n");
	if(ctx->sha1->final != 0) 
		 fprintf(fp,"final %lx\n",(void*)ctx->sha1->final-tmp);
	else 
		 fprintf(fp,"final 0\n");
	if(ctx->sha1->copy != 0) 
		 fprintf(fp,"copy %lx\n",(void*)ctx->sha1->copy-tmp);
	else 
		 fprintf(fp,"copy 0\n");
	if(ctx->sha1->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->sha1->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->sha1->sign != 0) 
		 fprintf(fp,"sign %lx\n",(void*)ctx->sha1->sign-tmp);
	else 
		 fprintf(fp,"sign 0\n");
	if(ctx->sha1->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->sha1->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->sha1->md_ctrl != 0) 
		 fprintf(fp,"md_ctrl %lx\n",(void*)ctx->sha1->md_ctrl-tmp);
	else 
		 fprintf(fp,"md_ctrl 0\n");
	if(ctx->info_callback != 0) 
		 fprintf(fp,"info_callback %lx\n",(void*)ctx->info_callback-tmp);
	else 
		 fprintf(fp,"info_callback 0\n");
	if(ctx->msg_callback != 0) 
		 fprintf(fp,"msg_callback %lx\n",(void*)ctx->msg_callback-tmp);
	else 
		 fprintf(fp,"msg_callback 0\n");
	if(ctx->default_verify_callback != 0) 
		 fprintf(fp,"default_verify_callback %lx\n",(void*)ctx->default_verify_callback-tmp);
	else 
		 fprintf(fp,"default_verify_callback 0\n");
	if(ctx->tlsext_servername_callback != 0) 
		 fprintf(fp,"tlsext_servername_callback %lx\n",(void*)ctx->tlsext_servername_callback-tmp);
	else 
		 fprintf(fp,"tlsext_servername_callback 0\n");
	if(ctx->tlsext_ticket_key_cb != 0) 
		 fprintf(fp,"tlsext_ticket_key_cb %lx\n",(void*)ctx->tlsext_ticket_key_cb-tmp);
	else 
		 fprintf(fp,"tlsext_ticket_key_cb 0\n");
	if(ctx->tlsext_status_cb != 0) 
		 fprintf(fp,"tlsext_status_cb %lx\n",(void*)ctx->tlsext_status_cb-tmp);
	else 
		 fprintf(fp,"tlsext_status_cb 0\n");
	if(ctx->tlsext_opaque_prf_input_callback != 0) 
		 fprintf(fp,"tlsext_opaque_prf_input_callback %lx\n",(void*)ctx->tlsext_opaque_prf_input_callback-tmp);
	else 
		 fprintf(fp,"tlsext_opaque_prf_input_callback 0\n");
	if(ctx->psk_client_callback != 0) 
		 fprintf(fp,"psk_client_callback %lx\n",(void*)ctx->psk_client_callback-tmp);
	else 
		 fprintf(fp,"psk_client_callback 0\n");
	if(ctx->psk_server_callback != 0) 
		 fprintf(fp,"psk_server_callback %lx\n",(void*)ctx->psk_server_callback-tmp);
	else 
		 fprintf(fp,"psk_server_callback 0\n");
	/*if(ctx->srp_ctx->TLS_ext_srp_username_callback != 0) 
		 fprintf(fp,"TLS_ext_srp_username_callback %lx\n",(void*)ctx->srp_ctx->TLS_ext_srp_username_callback-tmp);
	else 
		 fprintf(fp,"TLS_ext_srp_username_callback 0\n");
	if(ctx->srp_ctx->SRP_verify_param_callback != 0) 
		 fprintf(fp,"SRP_verify_param_callback %lx\n",(void*)ctx->srp_ctx->SRP_verify_param_callback-tmp);
	else 
		 fprintf(fp,"SRP_verify_param_callback 0\n");
	if(ctx->srp_ctx->SRP_give_srp_client_pwd_callback != 0) 
		 fprintf(fp,"SRP_give_srp_client_pwd_callback %lx\n",(void*)ctx->srp_ctx->SRP_give_srp_client_pwd_callback-tmp);
	else 
		 fprintf(fp,"SRP_give_srp_client_pwd_callback 0\n");*/
	if(ctx->next_protos_advertised_cb != 0) 
		 fprintf(fp,"next_protos_advertised_cb %lx\n",(void*)ctx->next_protos_advertised_cb-tmp);
	else 
		 fprintf(fp,"next_protos_advertised_cb 0\n");
	if(ctx->next_proto_select_cb != 0) 
		 fprintf(fp,"next_proto_select_cb %lx\n",(void*)ctx->next_proto_select_cb-tmp);
	else 
		 fprintf(fp,"next_proto_select_cb 0\n");

	/*if(ctx->client_cert_engine->rsa_meth->rsa_pub_enc != 0) 
		 fprintf(fp,"rsa_pub_enc %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_pub_enc-tmp);
	else 
		 fprintf(fp,"rsa_pub_enc 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_pub_dec != 0) 
		 fprintf(fp,"rsa_pub_dec %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_pub_dec-tmp);
	else 
		 fprintf(fp,"rsa_pub_dec 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_priv_enc != 0) 
		 fprintf(fp,"rsa_priv_enc %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_priv_enc-tmp);
	else 
		 fprintf(fp,"rsa_priv_enc 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_priv_dec != 0) 
		 fprintf(fp,"rsa_priv_dec %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_priv_dec-tmp);
	else 
		 fprintf(fp,"rsa_priv_dec 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_mod_exp != 0) 
		 fprintf(fp,"rsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_mod_exp-tmp);
	else 
		 fprintf(fp,"rsa_mod_exp 0\n");
	if(ctx->client_cert_engine->rsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->rsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->rsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->rsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->rsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->rsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_sign != 0) 
		 fprintf(fp,"rsa_sign %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_sign-tmp);
	else 
		 fprintf(fp,"rsa_sign 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_verify != 0) 
		 fprintf(fp,"rsa_verify %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_verify-tmp);
	else 
		 fprintf(fp,"rsa_verify 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_keygen != 0) 
		 fprintf(fp,"rsa_keygen %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_keygen-tmp);
	else 
		 fprintf(fp,"rsa_keygen 0\n");

	if(ctx->client_cert_engine->dsa_meth->dsa_do_sign != 0) 
		 fprintf(fp,"dsa_do_sign %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_do_sign-tmp);
	else 
		 fprintf(fp,"dsa_do_sign 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_sign_setup != 0) 
		 fprintf(fp,"dsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_sign_setup-tmp);
	else 
		 fprintf(fp,"dsa_sign_setup 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_do_verify != 0) 
		 fprintf(fp,"dsa_do_verify %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_do_verify-tmp);
	else 
		 fprintf(fp,"dsa_do_verify 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_mod_exp != 0) 
		 fprintf(fp,"dsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_mod_exp-tmp);
	else 
		 fprintf(fp,"dsa_mod_exp 0\n");
	if(ctx->client_cert_engine->dsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->dsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->dsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->dsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->dsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->dsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_paramgen != 0) 
		 fprintf(fp,"dsa_paramgen %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_paramgen-tmp);
	else 
		 fprintf(fp,"dsa_paramgen 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_keygen != 0) 
		 fprintf(fp,"dsa_keygen %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_keygen-tmp);
	else 
		 fprintf(fp,"dsa_keygen 0\n");

	if(ctx->client_cert_engine->dh_meth->generate_key != 0) 
		 fprintf(fp,"generate_key %lx\n",(void*)ctx->client_cert_engine->dh_meth->generate_key-tmp);
	else 
		 fprintf(fp,"generate_key 0\n");
	if(ctx->client_cert_engine->dh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->dh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->dh_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->dh_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->dh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->dh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->dh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->dh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->dh_meth->generate_params != 0) 
		 fprintf(fp,"generate_params %lx\n",(void*)ctx->client_cert_engine->dh_meth->generate_params-tmp);
	else 
		 fprintf(fp,"generate_params 0\n");

	if(ctx->client_cert_engine->ecdh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->ecdh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->ecdh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->ecdh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->ecdh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->ecdh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->ecdsa_meth->ecdsa_do_sign != 0) 
		 fprintf(fp,"ecdsa_do_sign %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->ecdsa_do_sign-tmp);
	else 
		 fprintf(fp,"ecdsa_do_sign 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->ecdsa_sign_setup != 0) 
		 fprintf(fp,"ecdsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->ecdsa_sign_setup-tmp);
	else 
		 fprintf(fp,"ecdsa_sign_setup 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->ecdsa_do_verify != 0) 
		 fprintf(fp,"ecdsa_do_verify %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->ecdsa_do_verify-tmp);
	else 
		 fprintf(fp,"ecdsa_do_verify 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->rand_meth->seed != 0) 
		 fprintf(fp,"seed %lx\n",(void*)ctx->client_cert_engine->rand_meth->seed-tmp);
	else 
		 fprintf(fp,"seed 0\n");
	if(ctx->client_cert_engine->rand_meth->bytes != 0) 
		 fprintf(fp,"bytes %lx\n",(void*)ctx->client_cert_engine->rand_meth->bytes-tmp);
	else 
		 fprintf(fp,"bytes 0\n");
	if(ctx->client_cert_engine->rand_meth->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->client_cert_engine->rand_meth->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->client_cert_engine->rand_meth->add != 0) 
		 fprintf(fp,"add %lx\n",(void*)ctx->client_cert_engine->rand_meth->add-tmp);
	else 
		 fprintf(fp,"add 0\n");
	if(ctx->client_cert_engine->rand_meth->pseudorand != 0) 
		 fprintf(fp,"pseudorand %lx\n",(void*)ctx->client_cert_engine->rand_meth->pseudorand-tmp);
	else 
		 fprintf(fp,"pseudorand 0\n");
	if(ctx->client_cert_engine->rand_meth->status != 0) 
		 fprintf(fp,"status %lx\n",(void*)ctx->client_cert_engine->rand_meth->status-tmp);
	else 
		 fprintf(fp,"status 0\n");


	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc != 0) 
		 fprintf(fp,"rsa_pub_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc-tmp);
	else 
		 fprintf(fp,"rsa_pub_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec != 0) 
		 fprintf(fp,"rsa_pub_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec-tmp);
	else 
		 fprintf(fp,"rsa_pub_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc != 0) 
		 fprintf(fp,"rsa_priv_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc-tmp);
	else 
		 fprintf(fp,"rsa_priv_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec != 0) 
		 fprintf(fp,"rsa_priv_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec-tmp);
	else 
		 fprintf(fp,"rsa_priv_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp != 0) 
		 fprintf(fp,"rsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp-tmp);
	else 
		 fprintf(fp,"rsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_sign != 0) 
		 fprintf(fp,"rsa_sign %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_sign-tmp);
	else 
		 fprintf(fp,"rsa_sign 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_verify != 0) 
		 fprintf(fp,"rsa_verify %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_verify-tmp);
	else 
		 fprintf(fp,"rsa_verify 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_keygen != 0) 
		 fprintf(fp,"rsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_keygen-tmp);
	else 
		 fprintf(fp,"rsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign != 0) 
		 fprintf(fp,"dsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign-tmp);
	else 
		 fprintf(fp,"dsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup != 0) 
		 fprintf(fp,"dsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup-tmp);
	else 
		 fprintf(fp,"dsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify != 0) 
		 fprintf(fp,"dsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify-tmp);
	else 
		 fprintf(fp,"dsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp != 0) 
		 fprintf(fp,"dsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp-tmp);
	else 
		 fprintf(fp,"dsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen != 0) 
		 fprintf(fp,"dsa_paramgen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen-tmp);
	else 
		 fprintf(fp,"dsa_paramgen 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_keygen != 0) 
		 fprintf(fp,"dsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_keygen-tmp);
	else 
		 fprintf(fp,"dsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dh_meth->generate_key != 0) 
		 fprintf(fp,"generate_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_key-tmp);
	else 
		 fprintf(fp,"generate_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->generate_params != 0) 
		 fprintf(fp,"generate_params %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_params-tmp);
	else 
		 fprintf(fp,"generate_params 0\n");

	if(ctx->client_cert_engine->prev->ecdh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign != 0) 
		 fprintf(fp,"ecdsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign-tmp);
	else 
		 fprintf(fp,"ecdsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup != 0) 
		 fprintf(fp,"ecdsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup-tmp);
	else 
		 fprintf(fp,"ecdsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify != 0) 
		 fprintf(fp,"ecdsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify-tmp);
	else 
		 fprintf(fp,"ecdsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->rand_meth->seed != 0) 
		 fprintf(fp,"seed %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->seed-tmp);
	else 
		 fprintf(fp,"seed 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->bytes != 0) 
		 fprintf(fp,"bytes %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->bytes-tmp);
	else 
		 fprintf(fp,"bytes 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->add != 0) 
		 fprintf(fp,"add %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->add-tmp);
	else 
		 fprintf(fp,"add 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->pseudorand != 0) 
		 fprintf(fp,"pseudorand %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->pseudorand-tmp);
	else 
		 fprintf(fp,"pseudorand 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->status != 0) 
		 fprintf(fp,"status %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->status-tmp);
	else 
		 fprintf(fp,"status 0\n");


	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc != 0) 
		 fprintf(fp,"rsa_pub_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc-tmp);
	else 
		 fprintf(fp,"rsa_pub_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec != 0) 
		 fprintf(fp,"rsa_pub_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec-tmp);
	else 
		 fprintf(fp,"rsa_pub_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc != 0) 
		 fprintf(fp,"rsa_priv_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc-tmp);
	else 
		 fprintf(fp,"rsa_priv_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec != 0) 
		 fprintf(fp,"rsa_priv_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec-tmp);
	else 
		 fprintf(fp,"rsa_priv_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp != 0) 
		 fprintf(fp,"rsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp-tmp);
	else 
		 fprintf(fp,"rsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_sign != 0) 
		 fprintf(fp,"rsa_sign %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_sign-tmp);
	else 
		 fprintf(fp,"rsa_sign 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_verify != 0) 
		 fprintf(fp,"rsa_verify %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_verify-tmp);
	else 
		 fprintf(fp,"rsa_verify 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_keygen != 0) 
		 fprintf(fp,"rsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_keygen-tmp);
	else 
		 fprintf(fp,"rsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign != 0) 
		 fprintf(fp,"dsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign-tmp);
	else 
		 fprintf(fp,"dsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup != 0) 
		 fprintf(fp,"dsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup-tmp);
	else 
		 fprintf(fp,"dsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify != 0) 
		 fprintf(fp,"dsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify-tmp);
	else 
		 fprintf(fp,"dsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp != 0) 
		 fprintf(fp,"dsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp-tmp);
	else 
		 fprintf(fp,"dsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen != 0) 
		 fprintf(fp,"dsa_paramgen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen-tmp);
	else 
		 fprintf(fp,"dsa_paramgen 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_keygen != 0) 
		 fprintf(fp,"dsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_keygen-tmp);
	else 
		 fprintf(fp,"dsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dh_meth->generate_key != 0) 
		 fprintf(fp,"generate_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_key-tmp);
	else 
		 fprintf(fp,"generate_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->generate_params != 0) 
		 fprintf(fp,"generate_params %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_params-tmp);
	else 
		 fprintf(fp,"generate_params 0\n");

	if(ctx->client_cert_engine->prev->ecdh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign != 0) 
		 fprintf(fp,"ecdsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign-tmp);
	else 
		 fprintf(fp,"ecdsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup != 0) 
		 fprintf(fp,"ecdsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup-tmp);
	else 
		 fprintf(fp,"ecdsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify != 0) 
		 fprintf(fp,"ecdsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify-tmp);
	else 
		 fprintf(fp,"ecdsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->rand_meth->seed != 0) 
		 fprintf(fp,"seed %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->seed-tmp);
	else 
		 fprintf(fp,"seed 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->bytes != 0) 
		 fprintf(fp,"bytes %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->bytes-tmp);
	else 
		 fprintf(fp,"bytes 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->add != 0) 
		 fprintf(fp,"add %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->add-tmp);
	else 
		 fprintf(fp,"add 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->pseudorand != 0) 
		 fprintf(fp,"pseudorand %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->pseudorand-tmp);
	else 
		 fprintf(fp,"pseudorand 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->status != 0) 
		 fprintf(fp,"status %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->status-tmp);
	else 
		 fprintf(fp,"status 0\n");*/

	
	//close the file
    fclose(fp);
}

int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    /* For the purposes of this demonstration, the password is "ibmdw" */
    printf("*** Callback function called\n");
    strcpy(buf, "ibmdw");
    return 1;
}

static void* header_handler(struct dl_phdr_info* info, size_t size, void* data)
{
	if(strstr(info->dlpi_name, "libssl") != NULL) {
		tmp = (void*) info->dlpi_addr;
		return (void*)info->dlpi_addr;
	}
    /*printf("name=%s (%d segments) address=%p\n",
            info->dlpi_name, info->dlpi_phnum, (void*)info->dlpi_addr);
    for (int j = 0; j < info->dlpi_phnum; j++) {
         printf("\t\t header %2d: address=%10p\n", j,
             (void*) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));
         printf("\t\t\t type=%u, flags=0x%X\n",
                 info->dlpi_phdr[j].p_type, info->dlpi_phdr[j].p_flags);
    }
    printf("\n");
    return 0;*/
}

int main()
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio, *abio, *out, *sbio;
    
    int (*callback)(char *, int, int, void *) = &password_callback;

    printf("Secure Programming with the OpenSSL API, Part 4:\n");
    printf("Serving it up in a secure manner\n\n");

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    printf("Attempting to create SSL context... ");
    ctx = SSL_CTX_new(SSLv3_server_method());
    
    if(ctx == NULL)
    {
        printf("Failed. Aborting.\n");
        return 0;
    }

    printf("\nLoading certificates...\n");
    SSL_CTX_set_default_passwd_cb(ctx, callback);
    if(!SSL_CTX_use_certificate_file(ctx, "TrustStore.pem", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx, "privatekey.key", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }
    dl_iterate_phdr(header_handler, NULL);

    printf("Attempting to create BIO object... ");
    bio = BIO_new_ssl(ctx, 0);
    if(bio == NULL)
    {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("\nAttempting to set up BIO for SSL...\n");
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    abio = BIO_new_accept("4422");
    BIO_set_accept_bios(abio, bio);
    
    take_function_pointers_backup(ctx);
    take_data_pointers_backup(ctx);
    
    printf("Waiting for incoming connection...\n");

    if(BIO_do_accept(abio) <= 0)
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    if(BIO_do_accept(abio) <= 0)
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    out = BIO_pop(abio);

    if(BIO_do_handshake(out) <= 0)
    {
        printf("Handshake failed.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    BIO_puts(out, "Hello\n");
    BIO_flush(out);

    BIO_free_all(out);
    BIO_free_all(bio);
    BIO_free_all(abio);

    SSL_CTX_free(ctx);
}


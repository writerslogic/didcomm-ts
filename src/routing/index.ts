export * from './forward.js';

const DIDCOMM_MESSAGING_SERVICE_TYPE = 'DIDCommMessaging';

export interface ServiceEndpointObject {
  uri: string;
  accept?: string[];
  routingKeys?: string[];
}

/** A DIDDoc serviceEndpoint, either the legacy bare-URI form or the current object form. */
export type ServiceEndpoint = string | ServiceEndpointObject;

export interface DIDDocService {
  id: string;
  type: string | string[];
  serviceEndpoint: ServiceEndpoint | ServiceEndpoint[];
}

export interface DIDDoc {
  id: string;
  service?: DIDDocService[];
}

/**
 * A resolved mediator chain for one of a recipient's devices/endpoints.
 * `mediators` is ordered innermost-first: `mediators[0]` is the mediator
 * closest to the recipient (wrap first), and the last entry is the one
 * whose endpoint the message is ultimately transmitted to.
 */
export interface RoutingPath {
  /** The service entry's fragment identifier (e.g. "mobile" for "#mobile"). */
  deviceId: string;
  /** The transport endpoint the fully-wrapped message is sent to. */
  endpoint: string;
  /** Ordered mediator DIDs to forward-wrap through, closest to the recipient first. */
  mediators: string[];
}

function serviceTypes(type: string | string[]): string[] {
  return Array.isArray(type) ? type : [type];
}

function fragmentOf(id: string): string {
  const hashIndex = id.indexOf('#');
  return hashIndex === -1 ? id : id.slice(hashIndex + 1);
}

function didFromKeyId(keyId: string): string {
  const hashIndex = keyId.indexOf('#');
  return hashIndex === -1 ? keyId : keyId.slice(0, hashIndex);
}

function resolveEndpointObject(endpoint: ServiceEndpoint | ServiceEndpoint[]): ServiceEndpointObject {
  const first = Array.isArray(endpoint) ? endpoint[0] : endpoint;
  if (first === undefined) {
    throw new Error('selectRoutingPath: service entry has an empty serviceEndpoint');
  }
  return typeof first === 'string' ? { uri: first } : first;
}

function toRoutingPath(service: DIDDocService): RoutingPath {
  const endpointObj = resolveEndpointObject(service.serviceEndpoint);
  return {
    deviceId: fragmentOf(service.id),
    endpoint: endpointObj.uri,
    mediators: (endpointObj.routingKeys ?? []).map(didFromKeyId),
  };
}

function messagingServices(didDoc: DIDDoc): DIDDocService[] {
  return (didDoc.service ?? []).filter((service) =>
    serviceTypes(service.type).includes(DIDCOMM_MESSAGING_SERVICE_TYPE),
  );
}

/**
 * Resolves the ordered mediator chain(s) to forward-wrap through for a
 * recipient's DIDDoc, per the DIDComm routing spec's handling of multiple
 * `DIDCommMessaging` service entries (one logical DID, several
 * devices/endpoints, each with its own `routingKeys`).
 *
 * - With `deviceHint`, returns the single matching device's {@link RoutingPath}
 *   (matched against the service entry's id fragment, e.g. "#mobile"), and
 *   throws if no service entry matches.
 * - Without `deviceHint`, returns every device's {@link RoutingPath}.
 */
export function selectRoutingPath(didDoc: DIDDoc, deviceHint: string): RoutingPath;
export function selectRoutingPath(didDoc: DIDDoc, deviceHint?: undefined): RoutingPath[];
export function selectRoutingPath(didDoc: DIDDoc, deviceHint?: string): RoutingPath | RoutingPath[] {
  const services = messagingServices(didDoc);

  if (deviceHint === undefined) {
    return services.map(toRoutingPath);
  }

  const match = services.find((service) => fragmentOf(service.id) === deviceHint || service.id === deviceHint);
  if (!match) {
    throw new Error(`selectRoutingPath: no DIDCommMessaging service entry found for device hint "${deviceHint}"`);
  }

  return toRoutingPath(match);
}

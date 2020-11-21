<?php
declare(strict_types=1);

namespace Stsbl\CollectWlanMacBundle\Rpc\Opsi;

use IServ\DeployBackendBundle\Entity\Host as DeployHost;
use IServ\DeployBackendBundle\Rpc\Opsi\AbstractHandler;
use IServ\DeployBackendBundle\Security\Authentication\ClientToken;
use IServ\HostBundle\Entity\Host;
use IServ\HostBundle\Entity\HostRepository;
use IServ\HostBundle\Events\HostEvents;
use IServ\HostBundle\Util\Network;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Stsbl\CollectWlanMacBundle\Exception\NoIpAvailableException;
use Stsbl\CollectWlanMacBundle\Service\IpSelector;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/*
 * The MIT License
 *
 * Copyright 2020 Felix Jacobi.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * @author Felix Jacobi <felix.jacobi@stsbl.de>
 * @license MIT license <https://opensource.org/licenses/MIT>
 */
final class CollectWlanMacAddressHandler extends AbstractHandler implements LoggerAwareInterface
{
    use LoggerAwareTrait;
    
    private const RESULT_FAIL = 'fail';
    private const RESULT_NOOP = 'noop';
    private const RESULT_ADDED = 'added';
    
    /**
     * {@inheritDoc}
     */
    protected $prefix = 'collect_wlan_mac_';

    /**
     * @var ClientToken
     */
    private $clientToken;

    /**
     * @var EventDispatcherInterface
     */
    private $dispatcher;
    
    /**
     * @var HostRepository
     */
    private $hostRepository;

    /**
     * @var IpSelector
     */
    private $selector;

    /**
     * @var ValidatorInterface
     */
    private $validator;

    public function __construct(
        ClientToken $clientToken,
        EventDispatcherInterface $dispatcher,
        HostRepository $hostRepository,
        IpSelector $selector,
        ValidatorInterface $validator
    ) {
        $this->clientToken = $clientToken;
        $this->dispatcher = $dispatcher;
        $this->hostRepository = $hostRepository;
        $this->selector = $selector;
        $this->validator = $validator;

        $this->logger = new NullLogger();
    }

    /**
     * Replaces of the current MAC address of the host entry associated with the deploy host with the supplied one.
     */
    public function collect_wlan_mac_individualise(string $macAddress): string
    {
        $deployHost = $this->clientToken->getHost();
        try {
            $macAddress = $this->validateMacAddress($macAddress, $deployHost);
        } catch (\InvalidArgumentException $e) {
            return self::RESULT_FAIL;
        }

        if (null !== $deployHost) {
            $host = $deployHost->getHost();
            $host->setMac($macAddress);

            return $this->validateAndSaveHost($host, $deployHost, $macAddress);
        }

        // Should never happen
        $this->logger->error('[Collect WLAN MAC] collect_wlan_mac_individualise called without deploy host for MAC address "{macAddress}".', ['macAddress' => $macAddress]);

        return self::RESULT_FAIL;
    }

    public function collect_wlan_mac_track(string $macAddress, string $name): string
    {
        $deployHost = $this->clientToken->getHost();
        try {
            $macAddress = $this->validateMacAddress($macAddress, $deployHost);
        } catch (\InvalidArgumentException $e) {
            return self::RESULT_FAIL;
        }

        if (null !== $hostEntity = $this->hostRepository->findOneBy(['mac' => $macAddress])) {
            $this->logger->warning('[Collect WLAN MAC] MAC address "{mac}" supplied by client "{host}" already in use by host "{host_entity}". Do not adding.', [
                'host' => $deployHost,
                'host_entity' => $hostEntity,
                'mac' => $macAddress,
            ]);
            
            return self::RESULT_NOOP;
        }

        try {
            $ipAddress = $this->selector->nextFreeIp();
        } catch (NoIpAvailableException $e) {
            $this->logger->error('[Collect WLAN MAC] Could not add host for MAC address "{mac}" supplied by client "{host}": Exception "{class}" with message "{message}" thrown..', [
                'exception' => $e,
                'class' => \get_class($e),
                'message' => $e->getMessage(),
                'host' => $deployHost,
                'mac' => $macAddress,
            ]);

            return self::RESULT_FAIL;
        }
        
        $wlanHost = Host::create($name, $ipAddress)->setMac($macAddress);

        return $this->validateAndSaveHost($wlanHost, $deployHost, $macAddress);
    }

    public function collect_wlan_mac_hostName(): string
    {
        if (!$this->clientToken->hasHost()) {
            return '';
        }

        return ($host = $this->clientToken->getHost()) ? $host->getIdentifier() : '';
    }

    public function collect_wlan_mac_inventoryNumber(): string
    {
        if (!$this->clientToken->hasHost()) {
            return '';
        }

        return ($host = $this->clientToken->getHost()) ? ($host->getHost()->getInventoryNumber() ?? '') : '';
    }

    /**
     * @throws \InvalidArgumentException If MAC address is not valid.
     */
    private function validateMacAddress(
        string $macAddress,
        ?DeployHost $deployHost
    ): string {
        $macAddress = Network::canonicalizeMac($macAddress);

        if (!Network::isMac($macAddress, true)) {
            $this->logger->error(
                '[Collect WLAN IPs] Invalid MAC address supplied by client "{host}": "{mac}"',
                [
                    'host' => $deployHost,
                    'mac' => $macAddress,
                ]
            );

            throw new \InvalidArgumentException('Invalid MAC address!');
        }

        return $macAddress;
    }

    private function validateAndSaveHost(Host $host, ?DeployHost $deployHost, string $macAddress): string
    {
        $violations = $this->validator->validate($host);
        if ($violations->count() > 0) {
            $this->logger->error(
                '[Collect WLAN MAC] Could not add host "{host_entity}" for MAC address "{mac}" supplied by client "{host}" as it causes violations: "{violations}".',
                [
                    'host' => $deployHost,
                    'host_entity' => $host,
                    'mac' => $macAddress,
                    'violations' => (string)$violations,
                ]
            );

            return self::RESULT_FAIL;
        }

        try {
            $this->hostRepository->save($host);
        } catch (\Throwable $e) {
            $this->logger->error(
                '[Collect WLAN MAC] Could not add host "{host_entity}" for MAC address "{mac}" supplied by client "{host}": Exception "{class}" with message "{message}" thrown..',
                [
                    'exception' => $e,
                    'class' => \get_class($e),
                    'message' => $e->getMessage(),
                    'host' => $deployHost,
                    'host_entity' => $host,
                    'mac' => $macAddress,
                ]
            );

            return self::RESULT_FAIL;
        }

        // Yip, the event object is completely useless and unused!
        $this->dispatcher->dispatch(
            new class {
            },
            HostEvents::HOST_CHANGED
        );

        return self::RESULT_ADDED;
    }
}

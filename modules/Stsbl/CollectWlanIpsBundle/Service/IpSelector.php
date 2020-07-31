<?php
declare(strict_types=1);

namespace Stsbl\CollectWlanIpsBundle\Service;

use Doctrine\Common\Collections\ArrayCollection;
use IServ\CoreBundle\Service\Config;
use IServ\HostBundle\Entity\Host;
use IServ\HostBundle\Entity\HostRepository;
use Stsbl\CollectWlanIpsBundle\Exception\NoIpAvailableException;
use Symfony\Component\HttpFoundation\IpUtils;

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
final class IpSelector
{
    private const CONFIG_VARIABLE = 'CollectWlanIpsRange';

    /**
     * @var Config
     */
    private $config;

    /**
     * @var HostRepository
     */
    private $hostRepository;

    public function __construct(Config $config, HostRepository $hostRepository)
    {
        $this->config = $config;
        $this->hostRepository = $hostRepository;
    }

    /**
     * @return string The next free IP address
     * @throws NoIpAvailableException If... the exception name says it.
     */
    public function nextFreeIp(): string
    {
        // Extract the IP part from the range and use it as the start IP
        $ip = \strtok($this->config->get(self::CONFIG_VARIABLE), '/');
        // Skip the first .0 IP
        $ip = ((\ip2long($ip) & 0xFF) === 0) ? $this->incrementIp($ip) : $ip;

        $hosts = new ArrayCollection($this->hostRepository->findAll());

        do {
            $ip = $this->incrementIp($ip);
        } while ($hosts->exists(
            static function ($key, Host $item) use ($ip) {
                return $item->getIp() === $ip;
            }
        ));

        if (false === $ip) {
            throw new NoIpAvailableException('No IP address available.');
        }

    }
    /**
     * @return string|bool New IP or FALSE if out of range
     */
    private function incrementIp(string $ip)
    {
        // don't allow .0 or .255 IPs as XP doesn't conform to RFCs :|
        do {
            $ip = \long2ip(\ip2long($ip) + 1);
        } while ((\ip2long($ip) & 0xFF) === 0 || (\ip2long($ip) & 0xFF) === 255);

        # check if the IP is still inside the range
        if (!IpUtils::checkIp($ip, $this->config->get(self::CONFIG_VARIABLE))) {
            return false;
        }

        return $ip;
    }
}

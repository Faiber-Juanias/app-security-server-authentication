package com.security.appsecurityserverauthentication.repositories;

import com.security.appsecurityserverauthentication.entities.PartnerEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;
import java.util.Optional;

@Repository
public interface IPartnerRepository extends JpaRepository<PartnerEntity, BigInteger> {

    Optional<PartnerEntity> findByClientId(String clientId);

}
